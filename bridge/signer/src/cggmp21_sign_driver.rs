//! Live-mesh `Pevm` (secp256k1 / CGGMP21) **signing** driver (**C.3**): runs the
//! real cggmp21 threshold-ECDSA signing MPC across the chosen signer set over the
//! authenticated session mesh, producing the standard `(r, s)` signature the wBDX
//! contract verifies with `ecrecover`.
//!
//! The signing counterpart of [`crate::cggmp21_driver`] (keygen over the mesh).
//! [`crate::cggmp21_sign`] proves the signing math + `ecrecover` recovery in one
//! process; this module drives it **over a [`SessionTransport`]** with the same
//! `round_based` sync state-machine pump and connection barrier as the keygen
//! driver. Each cggmp21 message rides inside a `SessionMsg::Round` frame on the
//! `Pevm` leg, inheriting per-message ed25519 auth (S4) and per-leg isolation (S14).
//!
//! **Index translation.** cggmp21 signing numbers the parties `0..t` *within the
//! signer set*, not by committee index: `signing(eid, i, parties, share)` takes
//! `i` = this signer's position in `parties`, and `parties[pos]` = that signer's
//! keygen index. The mesh, however, routes by committee index. So at the mesh
//! boundary this driver maps signing-position → committee index on send
//! (`OneParty(pos)` → `send_to(signers[pos])`) and committee index → signing
//! position on receive. `signers` is sorted so every node agrees on the mapping.
//!
//! Requires **complete** key shares (keygen + aux-info); producing those over the
//! mesh is the aux-info driver (a follow-on) — see [`crate::cggmp21_dkg_sign`] for
//! the full no-dealer chain proven in one process. Built under
//! `--features live-pevm-dkg` (cggmp21 + omq-mesh). Messages use `serde_json`.
//!
//! The `round_based 0.4` usage matches [`crate::cggmp21_driver`] exactly; the same
//! two adjust-to-pin spots apply (`MessageDestination` variant names; extra
//! `ProceedResult` arms).

use crate::committee::CommitteeView;
use crate::dkg_driver::{send_round, DriverError};
use crate::transport::Leg;
use crate::wire::{Dest, SessionMsg, SessionTransport, WireMsg};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId, KeyShare};
use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use sha3::{Digest, Keccak256};
use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The cggmp21 signing-protocol message (see [`crate::cggmp21_sign`]).
type SigningMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;

const CGGMP_BCAST: u8 = 1;
const CGGMP_P2P: u8 = 2;
/// Connection barrier. Body: the sender's run contribution ([`RUN_CONTRIBUTION_LEN`] bytes).
const CGGMP_HELLO: u8 = 9;

/// Fresh randomness each signer adds to a run's execution id.
///
/// Everything else in the id (committee, signer set, attempt, message) repeats whenever the
/// same duty is signed again: after a restart the coordinator's attempt counter starts from
/// 0, and the `sign` subcommand always passes 0. cggmp21 requires the id to be unique per
/// execution, so each signer draws a new contribution for every run and announces it in its
/// barrier HELLO, and the id is derived from all of them. One honest signer's fresh
/// contribution is enough to make the id new; none can be held back to force an old one.
const RUN_CONTRIBUTION_LEN: usize = 32;

/// Whether `msg` is the echo round's message: what a signer sends only when reliable
/// broadcast is enforced.
fn is_reliability_check(msg: &SigningMsg) -> bool {
    matches!(msg, cggmp21::signing::msg::Msg::ReliabilityCheck(_))
}

/// A stable 32-byte signing-session tag: the keccak digest being signed (what
/// `ecrecover` checks), so all signers route this signing's barrier frames to one session.
fn sign_tag(digest32: &[u8; 32]) -> [u8; 32] {
    *digest32
}

/// The execution id of one signing run.
///
/// Unique per run: the committee, the exact signer set, the retry attempt and the payload
/// identify the duty, and `contributions` (one per signer, in `parties` order) make this
/// run of it new. Two runs of the same duty never share a transcript.
fn signing_execution_id(
    committee_identity: &[u8],
    parties: &[u16],
    attempt: u32,
    preimage: &[u8],
    contributions: &[[u8; RUN_CONTRIBUTION_LEN]],
) -> [u8; 32] {
    let parties_bytes: Vec<u8> = parties.iter().flat_map(|p| p.to_le_bytes()).collect();
    let contributions_bytes: Vec<u8> = contributions.concat();
    crate::committee::execution_id(
        b"beldex-pevm-sign-v2",
        &[committee_identity, &parties_bytes, &attempt.to_le_bytes(), preimage, &contributions_bytes],
    )
}

/// The `payload_hash` the protocol rounds of one run travel under. Derived from the
/// execution id, so frames from any other run of the same duty (a run before a restart, a
/// peer still finishing an abandoned one) are not this run's and are never ingested.
fn round_tag(execution_id: &[u8; 32]) -> [u8; 32] {
    crate::committee::execution_id(b"beldex-pevm-sign-rounds-v1", &[execution_id])
}

/// A protocol frame that arrived during the barrier, kept with its tag until this run's
/// round tag is known: `(payload_hash, from, kind, body)`.
type EarlyFrame = ([u8; 32], u16, u8, Vec<u8>);

/// Drain the transport during the connection barrier: record each signer's run
/// contribution from its HELLO, and keep protocol frames for later.
///
/// A signer that announces two different contributions has started this signing twice
/// (it restarted) or is telling peers different things. Either way the signers could derive
/// different execution ids, so the run is abandoned and the coordinator retries it.
fn poll_barrier<T: SessionTransport>(
    transport: &mut T,
    epoch: u64,
    tag: [u8; 32],
    attempt: u32,
    signer_set: &BTreeSet<u16>,
    contributions: &mut std::collections::BTreeMap<u16, [u8; RUN_CONTRIBUTION_LEN]>,
    early: &mut Vec<EarlyFrame>,
) -> Result<(), DriverError> {
    while let Ok(Some(w)) = transport.poll() {
        if w.leg != Leg::Pevm || w.epoch != epoch || w.attempt != attempt || !signer_set.contains(&w.from) {
            continue; // not this duty, or not a signer
        }
        let SessionMsg::Round(payload) = &w.body else { continue };
        let Some((kind, rest)) = payload.split_first() else { continue };
        if *kind != CGGMP_HELLO {
            early.push((w.payload_hash, w.from, *kind, rest.to_vec()));
            continue;
        }
        if w.payload_hash != tag {
            continue;
        }
        let Ok(c) = <[u8; RUN_CONTRIBUTION_LEN]>::try_from(rest) else {
            continue; // a HELLO without a contribution cannot take part
        };
        match contributions.get(&w.from) {
            Some(prev) if *prev != c => {
                return Err(DriverError::Protocol(format!(
                    "signer {} announced two different run contributions for this signing (it \
                     restarted mid-run, or it is equivocating); abandoning the run so it is retried",
                    w.from
                )));
            }
            Some(_) => {}
            None => {
                contributions.insert(w.from, c);
            }
        }
    }
    Ok(())
}

fn wire(epoch: u64, tag: [u8; 32], attempt: u32, from: u16, kind: u8, msg_bytes: &[u8]) -> WireMsg {
    let mut payload = Vec::with_capacity(1 + msg_bytes.len());
    payload.push(kind);
    payload.extend_from_slice(msg_bytes);
    WireMsg {
        leg: Leg::Pevm,
        epoch,
        payload_hash: tag,
        attempt,
        from,
        body: SessionMsg::Round(payload),
    }
}

/// Run the real cggmp21 threshold signing to completion over `transport`, returning
/// the standard ECDSA signature as `r ‖ s` (64 bytes) and the compressed group key
/// `X` (33 bytes, → the wBDX signer address) so the caller can `ecrecover`.
///
/// `signers` are the committee/keygen indices of the participating signers (any
/// order; sorted internally); `self_index` must be one of them. `key_share_blob` is
/// this node's serialized **complete** `KeyShare`. `preimage` is hashed with keccak
/// (as the contract does) to form the signed digest.
/// `attempt` namespaces the mesh frames for this signing round (the coordinator's session
/// attempt), so concurrent attempts of one duty keep apart. It does not have to be new for
/// the run to be: the attempt counter restarts from 0 with the process, so the execution id
/// and the round frames are also bound to fresh per-run contributions from every signer
/// (see [`RUN_CONTRIBUTION_LEN`]), and a run never ingests another run's rounds.
#[allow(clippy::too_many_arguments)]
pub fn run_cggmp21_sign_over_transport<T: SessionTransport>(
    committee: &CommitteeView,
    self_index: u16,
    signers: &[u16],
    key_share_blob: &[u8],
    preimage: &[u8],
    attempt: u32,
    transport: &mut T,
    timeout: Duration,
) -> Result<([u8; 64], [u8; 33]), DriverError> {
    if !committee.can_sign() || !signers.contains(&self_index) {
        return Err(DriverError::BadCommittee);
    }
    // Sorted signer set → a mapping every node agrees on (position ↔ committee idx).
    let mut parties: Vec<u16> = signers.to_vec();
    parties.sort_unstable();
    parties.dedup();
    if parties.len() < committee.threshold {
        return Err(DriverError::BadCommittee);
    }
    let self_pos = parties
        .iter()
        .position(|&x| x == self_index)
        .ok_or(DriverError::BadCommittee)? as u16;
    let signer_set: BTreeSet<u16> = parties.iter().copied().collect();

    let epoch = committee.epoch;
    let digest32: [u8; 32] = Keccak256::digest(preimage).into();
    let tag = sign_tag(&digest32);

    // Deserialize this node's complete key share; capture the group key first.
    let key_share: KeyShare<Secp256k1, SecurityLevel128> = serde_json::from_slice(key_share_blob)
        .map_err(|e| DriverError::Protocol(format!("deserialize key share: {e}")))?;
    let x33: [u8; 33] = {
        use cggmp21::key_share::AnyKeyShare;
        let x = key_share.shared_public_key().to_bytes(true);
        let mut b = [0u8; 33];
        b.copy_from_slice(x.as_ref());
        b
    };

    // --- connection barrier (signer peers only) -------------------------------
    // Each HELLO carries this run's contribution to the execution id (see
    // RUN_CONTRIBUTION_LEN); the barrier ends once every signer's is known.
    let mut own_contribution = [0u8; RUN_CONTRIBUTION_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut own_contribution);
    let hello = wire(epoch, tag, attempt, self_index, CGGMP_HELLO, &own_contribution);
    let mut hello_failures = crate::wire::BarrierSendFailures::default();
    let mut contributions = std::collections::BTreeMap::from([(self_index, own_contribution)]);
    let mut early: Vec<EarlyFrame> = Vec::new();
    let barrier_deadline = Instant::now() + timeout.min(Duration::from_secs(60));
    loop {
        crate::wire::note_barrier_send(&mut hello_failures, transport.broadcast(&hello));
        poll_barrier(transport, epoch, tag, attempt, &signer_set, &mut contributions, &mut early)?;
        if contributions.len() >= parties.len() {
            break;
        }
        if Instant::now() >= barrier_deadline {
            let missing: Vec<u16> = parties.iter().copied().filter(|p| !contributions.contains_key(p)).collect();
            return Err(DriverError::Protocol(format!(
                "connection barrier timed out: no HELLO from signers {missing:?}{}",
                hello_failures.describe()
            )));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // Keep announcing for peers still in their barrier, and keep checking that nobody
    // announces a second contribution.
    for _ in 0..6 {
        crate::wire::note_barrier_send(&mut hello_failures, transport.broadcast(&hello));
        poll_barrier(transport, epoch, tag, attempt, &signer_set, &mut contributions, &mut early)?;
        std::thread::sleep(Duration::from_millis(100));
    }

    let ordered: Vec<[u8; RUN_CONTRIBUTION_LEN]> = parties.iter().map(|p| contributions[p]).collect();
    let eid_bytes = signing_execution_id(&committee.identity_bytes(), &parties, attempt, preimage, &ordered);
    let rtag = round_tag(&eid_bytes);

    // Channels bridge the protocol thread and this (mesh-pump) thread.
    let (out_tx, out_rx) = mpsc::channel::<Outgoing<SigningMsg>>();
    let (in_tx, in_rx) = mpsc::channel::<Incoming<SigningMsg>>();

    // Protocol thread: drive the cggmp21 signing state machine synchronously.
    let parties_for_proto = parties.clone();
    let preimage_owned = preimage.to_vec();

    let proto = std::thread::spawn(move || -> Result<[u8; 64], String> {
        let mut rng = rand::rngs::OsRng;
        let eid = ExecutionId::new(&eid_bytes);
        let data = DataToSign::<Secp256k1>::digest::<Keccak256>(&preimage_owned);
        let mut state = wrap_protocol(|party| async move {
            cggmp21::signing(eid, self_pos, &parties_for_proto, &key_share)
                // Round 1 must reach every signer identically. The mesh's broadcast is a send
                // to each peer, so a signer could hand peers different round-1 messages; the
                // extra echo round makes every signer confirm it saw what the others saw.
                // cggmp21 0.6.3 defaults this on; it is set here so the protection does not
                // rest on a library default.
                .enforce_reliable_broadcast(true)
                .sign(&mut rng, party, data)
                .await
        });
        // Whether this signer sent the echo round's message. A signature finished without
        // it was produced over an unchecked broadcast, so it is refused (see below).
        let mut sent_reliability_check = false;
        loop {
            match state.proceed() {
                ProceedResult::SendMsg(msg) => {
                    sent_reliability_check |= is_reliability_check(&msg.msg);
                    if out_tx.send(msg).is_err() {
                        return Err("outgoing channel closed".into());
                    }
                }
                ProceedResult::NeedsOneMoreMessage => match in_rx.recv() {
                    Ok(m) => {
                        if state.received_msg(m).is_err() {
                            return Err("state machine rejected a received message".into());
                        }
                    }
                    Err(_) => return Err("incoming channel closed (pump gone / timeout)".into()),
                },
                ProceedResult::Yielded => {}
                ProceedResult::Output(out) => {
                    let sig = out.map_err(|e| format!("signing failed: {e}"))?;
                    // Checked on every run, not assumed: if a cggmp21 upgrade ignored or
                    // renamed the option, signing would otherwise go on without the echo
                    // round and nothing would say so.
                    if !sent_reliability_check {
                        return Err("signing finished without the reliable-broadcast echo round; \
                                    refusing the signature"
                            .into());
                    }
                    let mut rs = [0u8; 64];
                    rs[..32].copy_from_slice(sig.r.to_be_bytes().as_ref());
                    rs[32..].copy_from_slice(sig.s.to_be_bytes().as_ref());
                    return Ok(rs);
                }
                ProceedResult::Error(err) => return Err(format!("state machine error: {err}")),
            }
        }
    });

    // Mesh pump.
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 0;

    // Map a cggmp21 recipient position → committee index for mesh routing. Each frame is
    // sent once and never repeated, so every one must reach its recipients
    // (`send_round`). A broadcast goes to the other signers only: nobody else takes part,
    // and a committee member outside this round being offline must not stop it.
    let send_out = |transport: &mut T, out: Outgoing<SigningMsg>| -> Result<(), DriverError> {
        let bytes = serde_json::to_vec(&out.msg)
            .map_err(|e| DriverError::Protocol(format!("serialize outgoing: {e}")))?;
        match out.recipient {
            MessageDestination::AllParties => {
                let frame = wire(epoch, rtag, attempt, self_index, CGGMP_BCAST, &bytes);
                for &peer in parties.iter().filter(|&&p| p != self_index) {
                    send_round(transport, "sign", Dest::One(peer), &frame, deadline)?;
                }
            }
            MessageDestination::OneParty(pos) => {
                let &peer = parties.get(pos as usize).ok_or_else(|| {
                    DriverError::Protocol(format!("the protocol addressed signing position {pos}, outside the signer set"))
                })?;
                send_round(transport, "sign", Dest::One(peer), &wire(epoch, rtag, attempt, self_index, CGGMP_P2P, &bytes), deadline)?;
            }
        }
        Ok(())
    };

    // Replay barrier-buffered frames first (mapping sender committee idx → position). Only
    // this run's: a frame under another round tag belongs to another run of the duty.
    for (frame_tag, from, kind, bytes) in early.drain(..) {
        if frame_tag != rtag {
            continue;
        }
        if let (Some(sender_pos), Ok(msg)) = (
            parties.iter().position(|&x| x == from),
            serde_json::from_slice::<SigningMsg>(&bytes),
        ) {
            let msg_type = if kind == CGGMP_BCAST { MessageType::Broadcast } else { MessageType::P2P };
            let _ = in_tx.send(Incoming { id: next_id, sender: sender_pos as u16, msg_type, msg });
            next_id += 1;
        }
    }

    loop {
        while let Ok(out) = out_rx.try_recv() {
            if let Err(e) = send_out(transport, out) {
                drop(in_tx);
                let _ = proto.join();
                return Err(e);
            }
        }
        loop {
            let w = match transport.poll() {
                Ok(Some(w)) => w,
                Ok(None) => break,
                Err(_) => break,
            };
            // Barrier HELLOs travel under `tag`, so this also drops any late ones.
            if w.leg != Leg::Pevm || w.epoch != epoch || w.payload_hash != rtag || w.attempt != attempt {
                continue;
            }
            let Some(sender_pos) = parties.iter().position(|&x| x == w.from) else {
                continue; // not a signer
            };
            let SessionMsg::Round(payload) = &w.body else { continue };
            let Some((kind, msg_bytes)) = payload.split_first() else { continue };
            if *kind == CGGMP_HELLO {
                continue;
            }
            let Ok(msg) = serde_json::from_slice::<SigningMsg>(msg_bytes) else { continue };
            let msg_type = if *kind == CGGMP_BCAST {
                MessageType::Broadcast
            } else {
                MessageType::P2P
            };
            let _ = in_tx.send(Incoming { id: next_id, sender: sender_pos as u16, msg_type, msg });
            next_id += 1;
        }

        if proto.is_finished() {
            break;
        }
        if Instant::now() >= deadline {
            drop(in_tx);
            let _ = proto.join();
            return Err(DriverError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    // Drain any final outgoing messages.
    while let Ok(out) = out_rx.try_recv() {
        send_out(transport, out)?;
    }

    match proto.join() {
        Ok(Ok(rs)) => Ok((rs, x33)),
        Ok(Err(e)) => Err(DriverError::Protocol(e)),
        Err(_) => Err(DriverError::Protocol("protocol thread panicked".into())),
    }
}

/// Live-mesh assembly for the `Pevm` signing leg: build the authenticated OMQ mesh
/// (via the shared [`crate::dkg_driver::live::assemble_mesh`]) and run the signing.
/// Mirrors [`crate::cggmp21_driver::live::run_live_pevm`].
pub mod live {
    use super::*;
    use crate::dkg_driver::live::{assemble_mesh, MeshIdentity, PeerTransportAddr};

    #[allow(clippy::too_many_arguments)]
    pub fn run_live_pevm_sign(
        committee: &CommitteeView,
        self_index: u16,
        signers: &[u16],
        key_share_blob: &[u8],
        preimage: &[u8],
        attempt: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        timeout: Duration,
    ) -> Result<([u8; 64], [u8; 33]), DriverError> {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        run_cggmp21_sign_over_transport(
            committee,
            self_index,
            signers,
            key_share_blob,
            preimage,
            attempt,
            &mut transport,
            timeout,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MeshError, WireMsg};
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn committee(n: u16, t: u16) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        }
    }

    fn eth_addr_from_x33(x33: &[u8; 33]) -> [u8; 20] {
        let vk = VerifyingKey::from_sec1_bytes(x33).expect("valid point");
        let enc = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&enc.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash[12..]);
        a
    }

    #[derive(Clone)]
    struct SharedBus {
        inboxes: Arc<Vec<Mutex<VecDeque<WireMsg>>>>,
        /// Every frame delivered, with its recipient: a recording of the run.
        log: Arc<Mutex<Vec<(u16, WireMsg)>>>,
    }
    struct BusEndpoint {
        bus: SharedBus,
        me: u16,
    }
    impl SharedBus {
        fn new(n: u16) -> SharedBus {
            SharedBus {
                inboxes: Arc::new((0..n).map(|_| Mutex::new(VecDeque::new())).collect()),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }
        fn endpoint(&self, me: u16) -> BusEndpoint {
            BusEndpoint { bus: self.clone(), me }
        }
    }
    impl SessionTransport for BusEndpoint {
        fn broadcast(&mut self, msg: &WireMsg) -> Result<(), MeshError> {
            for (i, inbox) in self.bus.inboxes.iter().enumerate() {
                if i as u16 != self.me {
                    inbox.lock().unwrap().push_back(msg.clone());
                    self.bus.log.lock().unwrap().push((i as u16, msg.clone()));
                }
            }
            Ok(())
        }
        fn send_to(&mut self, peer: u16, msg: &WireMsg) -> Result<(), MeshError> {
            self.bus.inboxes[peer as usize].lock().unwrap().push_back(msg.clone());
            self.bus.log.lock().unwrap().push((peer, msg.clone()));
            Ok(())
        }
        fn poll(&mut self) -> Result<Option<WireMsg>, MeshError> {
            Ok(self.bus.inboxes[self.me as usize].lock().unwrap().pop_front())
        }
    }

    /// Trusted-dealer complete shares → **sign over the shared-memory mesh through
    /// the real driver** → the aggregate `ecrecover`s to the wBDX signer address.
    /// (The share source is orthogonal; the no-dealer chain is `cggmp21_dkg_sign`.)
    /// Ignored (heavy MPC + threads).
    /// The check that refuses a signature made without the echo round must recognise the
    /// echo round's message; pinned here so a cggmp21 upgrade that renames or reshapes it
    /// fails to build or fails this test, rather than every signing at run time.
    #[test]
    fn the_echo_round_message_is_recognised() {
        let echo: SigningMsg = cggmp21::signing::msg::Msg::ReliabilityCheck(
            cggmp21::signing::msg::MsgReliabilityCheck(Default::default()),
        );
        assert!(is_reliability_check(&echo));
    }

    #[test]
    #[ignore = "runs the full cggmp21 signing MPC across threads"]
    fn cggmp21_signing_over_the_mesh_recovers_wbdx_address() {
        let (n, t) = (3u16, 2u16);
        let mut rng = rand::rngs::OsRng;

        // Complete shares (with aux-info) via the trusted dealer.
        let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
            .set_threshold(Some(t))
            .generate_shares(&mut rng)
            .expect("dealer shares");
        let blobs: Vec<Vec<u8>> =
            shares.iter().map(|s| serde_json::to_vec(s).expect("serialize share")).collect();

        let preimage = b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid";
        let digest32: [u8; 32] = Keccak256::digest(preimage).into();

        // Signer set: keygen indices 0 and 1.
        let signers = vec![0u16, 1u16];
        let bus = SharedBus::new(n);
        let committee = committee(n, t);

        let mut handles = Vec::new();
        for &idx in &signers {
            let mut ep = bus.endpoint(idx);
            let c = committee.clone();
            let blob = blobs[idx as usize].clone();
            let signers = signers.clone();
            let pre = preimage.to_vec();
            handles.push(std::thread::spawn(move || {
                run_cggmp21_sign_over_transport(
                    &c, idx, &signers, &blob, &pre, 0, &mut ep, Duration::from_secs(120),
                )
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().unwrap().expect("node signing"));
        }
        // Every signer produced the identical (r, s) and the same group key.
        let (rs0, x33) = results[0];
        assert!(results.iter().all(|(rs, x)| *rs == rs0 && *x == x33));

        // ecrecover the signer address (low-S, brute-force v) → the wBDX address.
        let expected = eth_addr_from_x33(&x33);
        let k_sig = K256Sig::from_slice(&rs0).expect("k256 sig");
        let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
        let mut recovered = None;
        for rec in [0u8, 1u8] {
            let id = RecoveryId::from_byte(rec).unwrap();
            if let Ok(vk) = VerifyingKey::recover_from_prehash(&digest32, &k_sig, id) {
                let enc = vk.to_encoded_point(false);
                let hash = Keccak256::digest(&enc.as_bytes()[1..]);
                let mut a = [0u8; 20];
                a.copy_from_slice(&hash[12..]);
                if a == expected {
                    recovered = Some(rec);
                    break;
                }
            }
        }
        assert!(recovered.is_some(), "ecrecover did not recover the wBDX signer address");
        eprintln!(
            "OK: {t}-of-{n} cggmp21 signing over the mesh -> ecrecover'd to wBDX signer 0x{} (v={})",
            expected.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            27 + recovered.unwrap()
        );
    }

    #[test]
    fn every_run_of_a_duty_has_its_own_execution_id() {
        let c = committee(3, 2).identity_bytes();
        let parties = [0u16, 1];
        let pre = b"mint";
        let id = |cs: &[[u8; 32]]| signing_execution_id(&c, &parties, 0, pre, cs);

        // Same duty, same attempt, same signers: only the runs' contributions differ.
        let first = id(&[[1; 32], [2; 32]]);
        assert_eq!(first, id(&[[1; 32], [2; 32]]), "every signer derives the same id from the same inputs");
        assert_ne!(first, id(&[[1; 32], [3; 32]]), "a fresh contribution from one signer makes a new id");
        assert_ne!(first, id(&[[2; 32], [1; 32]]), "contributions are bound to the signer that made them");

        // The duty's own identity still separates ids as before.
        assert_ne!(first, signing_execution_id(&c, &parties, 1, pre, &[[1; 32], [2; 32]]));
        assert_ne!(first, signing_execution_id(&c, &[0, 2], 0, pre, &[[1; 32], [2; 32]]));
        assert_ne!(first, signing_execution_id(&c, &parties, 0, b"other", &[[1; 32], [2; 32]]));

        // Rounds travel under a tag of the run, distinct from the barrier's.
        assert_ne!(round_tag(&first), round_tag(&id(&[[1; 32], [3; 32]])));
        assert_ne!(round_tag(&first), first);
    }

    fn hello(from: u16, attempt: u32, tag: [u8; 32], body: &[u8]) -> WireMsg {
        wire(2, tag, attempt, from, CGGMP_HELLO, body)
    }

    #[test]
    fn the_barrier_collects_each_signers_contribution_and_keeps_round_frames() {
        let tag = [7u8; 32];
        let bus = SharedBus::new(4);
        let mut me = bus.endpoint(0);
        let mut peer1 = bus.endpoint(1);
        let mut outsider = bus.endpoint(3);
        let signer_set: BTreeSet<u16> = [0u16, 1, 2].into_iter().collect();

        peer1.send_to(0, &hello(1, 0, tag, &[11; 32])).unwrap();
        peer1.send_to(0, &hello(1, 0, tag, &[11; 32])).unwrap(); // repeated, as the barrier does
        peer1.send_to(0, &hello(1, 0, tag, &[])).unwrap(); // no contribution: ignored
        peer1.send_to(0, &hello(1, 1, tag, &[99; 32])).unwrap(); // another attempt: ignored
        outsider.send_to(0, &hello(3, 0, tag, &[33; 32])).unwrap(); // not a signer: ignored
        peer1.send_to(0, &wire(2, [5; 32], 0, 1, CGGMP_BCAST, b"round")).unwrap();

        let mut contributions = std::collections::BTreeMap::new();
        let mut early = Vec::new();
        poll_barrier(&mut me, 2, tag, 0, &signer_set, &mut contributions, &mut early).unwrap();
        assert_eq!(contributions, std::collections::BTreeMap::from([(1u16, [11u8; 32])]));
        assert_eq!(early, vec![([5u8; 32], 1u16, CGGMP_BCAST, b"round".to_vec())]);
    }

    #[test]
    fn a_signer_announcing_a_second_contribution_abandons_the_run() {
        let tag = [7u8; 32];
        let bus = SharedBus::new(3);
        let mut me = bus.endpoint(0);
        let mut peer1 = bus.endpoint(1);
        let signer_set: BTreeSet<u16> = [0u16, 1, 2].into_iter().collect();

        // Peer 1 restarted mid-run: its HELLO from before the restart, then a new one.
        peer1.send_to(0, &hello(1, 0, tag, &[11; 32])).unwrap();
        peer1.send_to(0, &hello(1, 0, tag, &[12; 32])).unwrap();

        let mut contributions = std::collections::BTreeMap::new();
        let mut early = Vec::new();
        let e = poll_barrier(&mut me, 2, tag, 0, &signer_set, &mut contributions, &mut early).unwrap_err();
        assert!(matches!(&e, DriverError::Protocol(m) if m.contains("two different run contributions")), "{e:?}");
    }

    /// The restart case end to end. A duty is signed once; then the same duty is signed
    /// again with the same attempt and signers — what happens after a restart, when the
    /// attempt counter is back at 0 — while every round frame of the first run is delivered
    /// to the signers again ahead of the second run's. The second run must ignore them all
    /// and produce a valid signature of its own. With an execution id that did not change
    /// between runs, those frames carried the same id and tags and were taken as this run's.
    #[test]
    #[ignore = "runs the full cggmp21 signing MPC across threads, twice"]
    fn a_rerun_of_the_same_duty_ignores_the_earlier_runs_frames() {
        let (n, t) = (3u16, 2u16);
        let mut rng = rand::rngs::OsRng;
        let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
            .set_threshold(Some(t))
            .generate_shares(&mut rng)
            .expect("dealer shares");
        let blobs: Vec<Vec<u8>> =
            shares.iter().map(|s| serde_json::to_vec(s).expect("serialize share")).collect();
        let preimage = b"the same mint, signed twice".to_vec();
        let signers = vec![0u16, 1u16];
        let committee = committee(n, t);

        let run = |bus: &SharedBus| -> Vec<([u8; 64], [u8; 33])> {
            let handles: Vec<_> = signers
                .iter()
                .map(|&idx| {
                    let mut ep = bus.endpoint(idx);
                    let (c, blob, signers, pre) =
                        (committee.clone(), blobs[idx as usize].clone(), signers.clone(), preimage.clone());
                    std::thread::spawn(move || {
                        run_cggmp21_sign_over_transport(&c, idx, &signers, &blob, &pre, 0, &mut ep, Duration::from_secs(120))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap().expect("node signing")).collect()
        };

        let first_bus = SharedBus::new(n);
        let first = run(&first_bus);

        // The second run's signers find the first run's protocol rounds already waiting.
        let second_bus = SharedBus::new(n);
        let stale: Vec<(u16, WireMsg)> = first_bus.log.lock().unwrap().clone();
        let mut replayed = 0;
        for (to, msg) in stale {
            let SessionMsg::Round(p) = &msg.body else { continue };
            if p.first() != Some(&CGGMP_HELLO) {
                second_bus.inboxes[to as usize].lock().unwrap().push_back(msg);
                replayed += 1;
            }
        }
        assert!(replayed > 0, "the first run's rounds were recorded");
        let second = run(&second_bus);

        let digest32: [u8; 32] = Keccak256::digest(&preimage).into();
        let x33 = second[0].1;
        assert!(second.iter().all(|r| *r == second[0]), "the signers agree on the second signature");
        assert_eq!(x33, first[0].1);
        let sig = K256Sig::from_slice(&second[0].0).expect("k256 sig");
        let sig = sig.normalize_s().unwrap_or(sig);
        let recovers = [0u8, 1].iter().any(|&v| {
            VerifyingKey::recover_from_prehash(&digest32, &sig, RecoveryId::from_byte(v).unwrap())
                .map(|vk| eth_addr_from_x33(&vk.to_encoded_point(true).as_bytes().try_into().unwrap()) == eth_addr_from_x33(&x33))
                .unwrap_or(false)
        });
        assert!(recovers, "the second run's signature recovers to the wBDX signer");
        assert_ne!(first[0].0, second[0].0, "fresh nonces: a new signature, not the first one again");
    }
}

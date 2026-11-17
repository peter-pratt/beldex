//! Live-mesh FROST (`Pgw`) DKG driver (**C.2**): runs the real `frost-ed25519`
//! `part1/part2/part3` rounds across the committee over the authenticated session
//! mesh, storing this node's resulting share.
//!
//! [`crate::dkg`] owns the *orchestration* (round-progress gating, per-leg
//! namespacing, transcript, store hand-off). [`crate::frost_dkg`] proves the
//! crate rounds produce a consensus-verifiable key in one process. This module is
//! the missing middle: the driver that actually **exchanges DKG packages over a
//! [`SessionTransport`]** — so the same code runs in-process against a test bus
//! and, unchanged, over the curve-authenticated [`crate::omq_mesh`] against a live
//! devnet committee.
//!
//! Design: a **step-based state machine**, not a hidden async loop, so it is
//! deterministically testable. [`FrostDkgDriver::begin`] runs round 1 and returns
//! the frames to send; [`FrostDkgDriver::on_wire`] ingests one authenticated
//! inbound frame and returns any frames to send in response (running round 2 the
//! moment all round-1 packages are in, and round 3 the moment all addressed
//! round-2 packages are in). [`run_over_transport`] is the thin blocking wrapper
//! that pumps those steps over a real socket transport with a timeout.
//!
//! DKG packages ride inside `SessionMsg::Round(encode_dkg_payload(round, pkg))`
//! (leg `Pgw`), so they inherit the mesh's per-message authentication (S4) and
//! per-leg isolation (S14) with no new wire surface. **No key is ever assembled
//! (S1):** each member runs its own `part3` to its own `KeyPackage`; only that
//! member's share is stored.
//!
//! Built under `--features tss-integration` (the driver is transport-agnostic via
//! [`SessionTransport`]); the live binary path additionally needs `omq-mesh` +
//! `omq-client` (see the `live-dkg` feature and `main.rs`).
//!
//! NOTE: the `frost-ed25519` 2.x DKG package `serialize`/`deserialize` API is used
//! as documented; if the pinned version differs, adjust here — isolated behind the
//! feature, exactly like `frost_dkg` / `cggmp21_interop`.

use crate::committee::CommitteeView;
use crate::dkg::{decode_dkg_payload, encode_dkg_payload, DkgLeg, DkgSession, DKG_HELLO, DKG_ROUND1, DKG_ROUND2};
use crate::share_store::ShareStore;
use crate::transport::Leg;
use crate::wire::{SessionMsg, SessionTransport, WireMsg};
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

type Id = frost::Identifier;

/// A frame the driver wants sent: to everyone, or to one peer by committee index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Round-1 commitment package — broadcast to all peers.
    Broadcast(WireMsg),
    /// Round-2 package — sent privately to the one peer it is addressed to.
    To(u16, WireMsg),
}

/// Driver failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// `self_index` is not in the committee, or the committee cannot sign.
    BadCommittee,
    /// A `frost` round call failed (bad package from a peer, etc.).
    Frost(String),
    /// A peer's package did not decode.
    BadPackage(u16),
    /// A frame for the wrong leg reached the FROST driver (S14).
    WrongLeg,
    /// The DKG did not complete within the deadline.
    Timeout,
    /// Mesh transport assembly / bind failure (live path).
    Transport(String),
    /// An MPC protocol / serialization failure (the cggmp21 live driver).
    Protocol(String),
    /// A protocol frame could not be delivered to some peers within
    /// [`crate::wire::SEND_RETRY_WINDOW`]: the run cannot complete without them, so it
    /// stops here and names them rather than waiting out its timeout.
    Undelivered(String),
}

/// Run a driver over a [`crate::wire::Budgeted`] view of `transport`, and if a peer went
/// over its frame budget, say so in the error rather than leaving a bare timeout.
pub(crate) fn with_frame_budget<T, Out>(
    transport: &mut T,
    run: impl FnOnce(&mut crate::wire::Budgeted<'_, T>) -> Result<Out, DriverError>,
) -> Result<Out, DriverError>
where
    T: SessionTransport + ?Sized,
{
    let mut budgeted = crate::wire::Budgeted::new(transport);
    let result = run(&mut budgeted);
    match (result, budgeted.flooder()) {
        (Err(e), Some(peer)) => Err(DriverError::Protocol(format!(
            "peer {peer} sent more than {} frames in this run and the rest were dropped; the run \
             could not finish ({e:?})",
            crate::wire::MAX_FRAMES_PER_PEER_PER_RUN
        ))),
        (r, _) => r,
    }
}

/// Send one protocol frame that will not be sent again, or stop the run.
///
/// Every MPC driver sends each round's frames exactly once, so a frame a peer never
/// receives leaves the run waiting for an answer that cannot come. This re-sends to the
/// peers that missed it for up to [`crate::wire::SEND_RETRY_WINDOW`] (never past the run's
/// own `deadline`), and turns a peer that stays unreachable into
/// [`DriverError::Undelivered`] naming it.
pub(crate) fn send_round<T: SessionTransport + ?Sized>(
    transport: &mut T,
    what: &str,
    dest: crate::wire::Dest,
    msg: &crate::wire::WireMsg,
    deadline: Instant,
) -> Result<(), DriverError> {
    let within = crate::wire::SEND_RETRY_WINDOW.min(deadline.saturating_duration_since(Instant::now()));
    crate::wire::deliver(transport, dest, msg, within)
        .map_err(|e| DriverError::Undelivered(format!("{what}: {e}")))
}

/// One node's FROST DKG, driven a frame at a time.
pub struct FrostDkgDriver {
    self_index: u16,
    self_id: Id,
    n: u16,
    t: u16,
    epoch: u64,
    key_generation: u32,
    payload_hash: [u8; 32],
    id_to_index: BTreeMap<Id, u16>,

    session: DkgSession,

    // frost round state
    r1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    r2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    r1_pkgs: BTreeMap<Id, frost::keys::dkg::round1::Package>, // received incl. own
    r2_to_me: BTreeMap<Id, frost::keys::dkg::round2::Package>, // addressed to me

    // result
    key_package_blob: Option<Vec<u8>>,
    pubkey_package_blob: Option<Vec<u8>>,
    group_vk: Option<[u8; 32]>,
}

/// Map a 0-based committee index to a FROST identifier (`index + 1`).
fn id_of(index: u16) -> Result<Id, DriverError> {
    (index + 1)
        .try_into()
        .map_err(|_| DriverError::BadCommittee)
}

/// A stable 32-byte DKG session tag so all nodes route this ceremony's frames to
/// one session (epoch ‖ key_generation, zero-padded — not a security value).
fn dkg_payload_hash(epoch: u64, key_generation: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&epoch.to_le_bytes());
    h[8..12].copy_from_slice(&key_generation.to_le_bytes());
    h
}

impl FrostDkgDriver {
    /// Begin the ceremony: run round 1 and return this node's round-1 broadcast.
    pub fn begin<R: RngCore + CryptoRng>(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        rng: &mut R,
    ) -> Result<(FrostDkgDriver, Vec<Outbound>), DriverError> {
        let n = committee.members.len() as u16;
        let t = committee.threshold as u16;
        if (self_index as usize) >= committee.members.len() || !committee.can_sign() {
            return Err(DriverError::BadCommittee);
        }
        let self_id = id_of(self_index)?;
        let mut id_to_index = BTreeMap::new();
        for i in 0..n {
            id_to_index.insert(id_of(i)?, i);
        }

        let session =
            DkgSession::start(committee, DkgLeg::Pgw, key_generation, self_index as usize)
                .map_err(|_| DriverError::BadCommittee)?;

        // Round 1: commit. (Reborrow the RNG so the caller keeps its `&mut`.)
        let (r1_secret, r1_pkg) = frost::keys::dkg::part1(self_id, n, t, &mut *rng)
            .map_err(|e| DriverError::Frost(format!("part1: {e}")))?;

        let mut driver = FrostDkgDriver {
            self_index,
            self_id,
            n,
            t,
            epoch: committee.epoch,
            key_generation,
            payload_hash: dkg_payload_hash(committee.epoch, key_generation),
            id_to_index,
            session,
            r1_secret: Some(r1_secret),
            r2_secret: None,
            r1_pkgs: BTreeMap::new(),
            r2_to_me: BTreeMap::new(),
            key_package_blob: None,
            pubkey_package_blob: None,
            group_vk: None,
        };

        // Record our own round-1 package (counts toward the all-`n` gate).
        let own_bytes = r1_pkg
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize r1: {e}")))?;
        driver.r1_pkgs.insert(self_id, r1_pkg);
        let _ = driver.session.on_round1(self_index as usize, own_bytes.clone());

        let broadcast = driver.wire(DKG_ROUND1, &own_bytes);
        Ok((driver, vec![Outbound::Broadcast(broadcast)]))
    }

    /// Whether this node has produced and stored its share.
    pub fn is_complete(&self) -> bool {
        self.key_package_blob.is_some()
    }

    /// The group ed25519 verifying key `Y` (gateway `owner_key`), once complete.
    pub fn group_pubkey(&self) -> Option<[u8; 32]> {
        self.group_vk
    }

    /// This node's serialized `KeyPackage` (its DKG'd share), once complete — the
    /// input the signing driver loads. Persist under secure custody in production.
    pub fn key_package_blob(&self) -> Option<Vec<u8>> {
        self.key_package_blob.clone()
    }

    /// The serialized group `PublicKeyPackage` (all members' verifying shares + the
    /// group key), once complete. Public, but needed to aggregate a signature — so
    /// it is persisted alongside the share for the signing driver.
    pub fn pubkey_package_blob(&self) -> Option<Vec<u8>> {
        self.pubkey_package_blob.clone()
    }

    /// The signing threshold `t + 1` for this DKG.
    pub fn threshold(&self) -> u16 {
        self.t
    }

    /// The key-generation number this ceremony produces (the share-store version).
    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    /// Persist this node's own key share to the store at the key-generation
    /// version (S1: its own share only). Call once complete.
    pub fn store_share<S: ShareStore>(&self, store: &mut S) {
        if let Some(blob) = &self.key_package_blob {
            self.session.store_share(store, blob.clone());
        }
    }

    /// Ingest one authenticated inbound frame; return any frames to send next.
    pub fn on_wire<R: RngCore + CryptoRng>(
        &mut self,
        msg: &WireMsg,
        rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        if msg.leg != Leg::Pgw {
            return Err(DriverError::WrongLeg);
        }
        // Not for this ceremony (different epoch / key generation) — ignore.
        if msg.epoch != self.epoch || msg.payload_hash != self.payload_hash {
            return Ok(vec![]);
        }
        let from = msg.from;
        let SessionMsg::Round(payload) = &msg.body else {
            return Ok(vec![]); // DKG only uses Round frames
        };
        let Some((round, pkg)) = decode_dkg_payload(payload) else {
            return Ok(vec![]);
        };

        match round {
            DKG_ROUND1 => self.ingest_round1(from, pkg, rng),
            DKG_ROUND2 => self.ingest_round2(from, pkg, rng),
            _ => Ok(vec![]),
        }
    }

    fn ingest_round1<R: RngCore + CryptoRng>(
        &mut self,
        from: u16,
        pkg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        let from_id = id_of(from)?;
        if from_id == self.self_id || self.r1_pkgs.contains_key(&from_id) {
            return Ok(vec![]); // own / duplicate
        }
        let package = frost::keys::dkg::round1::Package::deserialize(pkg)
            .map_err(|_| DriverError::BadPackage(from))?;
        self.r1_pkgs.insert(from_id, package);
        let _ = self.session.on_round1(from as usize, pkg.to_vec());

        // When every member's round-1 package is in, run round 2 and emit the
        // per-recipient addressed packages.
        if self.r2_secret.is_none() && self.r1_pkgs.len() as u16 == self.n {
            return self.run_round2(rng);
        }
        Ok(vec![])
    }

    fn run_round2<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        // part2 needs the OTHER members' round-1 packages (never our own).
        let others: BTreeMap<Id, _> = self
            .r1_pkgs
            .iter()
            .filter(|(k, _)| **k != self.self_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let secret = self.r1_secret.take().ok_or(DriverError::BadCommittee)?;
        let (r2_secret, r2_out) = frost::keys::dkg::part2(secret, &others)
            .map_err(|e| DriverError::Frost(format!("part2: {e}")))?;
        self.r2_secret = Some(r2_secret);

        // Send each recipient its addressed round-2 package.
        let mut outs = Vec::with_capacity(r2_out.len());
        for (recipient_id, pkg) in r2_out {
            let idx = *self
                .id_to_index
                .get(&recipient_id)
                .ok_or(DriverError::BadCommittee)?;
            let bytes = pkg
                .serialize()
                .map_err(|e| DriverError::Frost(format!("serialize r2: {e}")))?;
            outs.push(Outbound::To(idx, self.wire(DKG_ROUND2, &bytes)));
        }
        // Any round-2 packages that arrived early can now be finalized.
        outs.extend(self.try_finalize()?);
        Ok(outs)
    }

    fn ingest_round2<R: RngCore + CryptoRng>(
        &mut self,
        from: u16,
        pkg: &[u8],
        _rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        let from_id = id_of(from)?;
        if self.r2_to_me.contains_key(&from_id) {
            return Ok(vec![]); // duplicate
        }
        let package = frost::keys::dkg::round2::Package::deserialize(pkg)
            .map_err(|_| DriverError::BadPackage(from))?;
        self.r2_to_me.insert(from_id, package);
        // Feed the session for the transcript once we are in the round-2 stage.
        let _ = self.session.on_round2(from as usize, pkg.to_vec());
        self.try_finalize()
    }

    /// Run `part3` once our own `part2` is done and every peer's addressed
    /// round-2 package is in; store the share and publish the group key.
    fn try_finalize(&mut self) -> Result<Vec<Outbound>, DriverError> {
        if self.key_package_blob.is_some() {
            return Ok(vec![]); // already done
        }
        if self.r2_secret.is_none() || (self.r2_to_me.len() as u16) != self.n - 1 {
            return Ok(vec![]); // not ready
        }
        let others_r1: BTreeMap<Id, _> = self
            .r1_pkgs
            .iter()
            .filter(|(k, _)| **k != self.self_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let r2_secret = self.r2_secret.as_ref().unwrap();
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(r2_secret, &others_r1, &self.r2_to_me)
                .map_err(|e| DriverError::Frost(format!("part3: {e}")))?;

        let blob = key_package
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize key package: {e}")))?;
        let pk_blob = pubkey_package
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize pubkey package: {e}")))?;
        let vk_vec = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize vk: {e}")))?;
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&vk_vec);

        self.key_package_blob = Some(blob);
        self.pubkey_package_blob = Some(pk_blob);
        self.group_vk = Some(vk);
        let _ = self.session.finalize(vk.to_vec());
        Ok(vec![]) // completion has no outbound frames
    }

    /// Build a DKG `WireMsg` (leg `Pgw`, this ceremony's session tag, our index).
    fn wire(&self, round: u8, package: &[u8]) -> WireMsg {
        WireMsg {
            leg: Leg::Pgw,
            epoch: self.epoch,
            payload_hash: self.payload_hash,
            attempt: 0,
            from: self.self_index,
            body: SessionMsg::Round(encode_dkg_payload(round, package)),
        }
    }
}

/// Blocking wrapper: run the FROST DKG to completion over `transport`, storing the
/// share, and return the group verifying key. Pumps [`FrostDkgDriver`] steps and
/// the transport's poll/send until complete or `timeout` elapses.
///
/// The transport is expected to already authenticate inbound frames (S4) — with
/// [`crate::omq_mesh::OmqPeerTransport::with_auth`], a forged `from` never reaches
/// here. Each round package is sent once and not repeated, so a peer that cannot be
/// reached is retried for a bounded window and then fails the run by name
/// ([`DriverError::Undelivered`]).
pub fn run_over_transport<T, S, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    store: &mut S,
    rng: &mut R,
    timeout: Duration,
) -> Result<[u8; 32], DriverError>
where
    T: SessionTransport,
    S: ShareStore,
    R: RngCore + CryptoRng,
{
    let driver = drive_to_completion(committee, self_index, key_generation, transport, rng, timeout)?;
    driver.store_share(store);
    driver.group_pubkey().ok_or(DriverError::BadCommittee)
}

/// Like [`run_over_transport`], but instead of storing into a [`ShareStore`] it
/// returns the completed key material — the group verifying key, this node's
/// serialized `KeyPackage`, and the group `PublicKeyPackage` — so a caller can
/// persist all three for a later standalone signing session (the `sign`
/// subcommand). No key is assembled (S1); the returned `KeyPackage` is this node's
/// share only, and the `PublicKeyPackage` is public.
pub fn run_over_transport_capture<T, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    rng: &mut R,
    timeout: Duration,
) -> Result<([u8; 32], Vec<u8>, Vec<u8>), DriverError>
where
    T: SessionTransport,
    R: RngCore + CryptoRng,
{
    let driver = drive_to_completion(committee, self_index, key_generation, transport, rng, timeout)?;
    let vk = driver.group_pubkey().ok_or(DriverError::BadCommittee)?;
    let kp = driver.key_package_blob().ok_or(DriverError::BadCommittee)?;
    let pk = driver.pubkey_package_blob().ok_or(DriverError::BadCommittee)?;
    Ok((vk, kp, pk))
}

/// Shared driver loop: begin the ceremony, pump [`FrostDkgDriver`] steps over the
/// transport until complete or `timeout` elapses, and return the finished driver.
fn drive_to_completion<T, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    rng: &mut R,
    timeout: Duration,
) -> Result<FrostDkgDriver, DriverError>
where
    T: SessionTransport,
    R: RngCore + CryptoRng,
{
    with_frame_budget(transport, |t| drive_unbudgeted(committee, self_index, key_generation, t, rng, timeout))
}

fn drive_unbudgeted<T, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    rng: &mut R,
    timeout: Duration,
) -> Result<FrostDkgDriver, DriverError>
where
    T: SessionTransport,
    R: RngCore + CryptoRng,
{
    let (mut driver, first) = FrostDkgDriver::begin(committee, self_index, key_generation, rng)?;
    let deadline = Instant::now() + timeout;
    let early = connection_barrier(&driver, transport, timeout)?;
    send_all(transport, first, deadline)?;
    for msg in early {
        let outs = driver.on_wire(&msg, rng)?;
        send_all(transport, outs, deadline)?;
    }

    while !driver.is_complete() {
        if Instant::now() >= deadline {
            return Err(DriverError::Timeout);
        }
        match transport.poll() {
            Ok(Some(msg)) => {
                let outs = driver.on_wire(&msg, rng)?;
                send_all(transport, outs, deadline)?;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            // A single dropped/garbled/forged frame must not abort the ceremony.
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    Ok(driver)
}

/// Wait until every peer has been heard from before round 1 goes out. Each round package
/// is sent once, so one sent to a peer whose listener is not up yet is lost and the run can
/// only time out; members started a few seconds apart would fail that way. Any frame of
/// this run proves its sender is up, and round frames that arrive meanwhile are returned
/// for the driver rather than dropped.
fn connection_barrier<T: SessionTransport>(
    driver: &FrostDkgDriver,
    transport: &mut T,
    timeout: Duration,
) -> Result<Vec<WireMsg>, DriverError> {
    let hello = driver.wire(DKG_HELLO, &[]);
    let mut failures = crate::wire::BarrierSendFailures::default();
    let mut seen: BTreeSet<u16> = BTreeSet::new();
    let mut early = Vec::new();
    let take = |msg: WireMsg, seen: &mut BTreeSet<u16>, early: &mut Vec<WireMsg>| {
        if msg.leg != Leg::Pgw || msg.epoch != driver.epoch || msg.payload_hash != driver.payload_hash {
            return;
        }
        if msg.from != driver.self_index {
            seen.insert(msg.from);
        }
        let is_hello = match &msg.body {
            SessionMsg::Round(p) => decode_dkg_payload(p).map(|(round, _)| round) == Some(DKG_HELLO),
            _ => false,
        };
        if !is_hello {
            early.push(msg);
        }
    };
    let barrier_deadline = Instant::now() + timeout.min(Duration::from_secs(60));
    loop {
        crate::wire::note_barrier_send(&mut failures, transport.broadcast(&hello));
        while let Ok(Some(msg)) = transport.poll() {
            take(msg, &mut seen, &mut early);
        }
        if seen.len() as u16 >= driver.n - 1 {
            break;
        }
        if Instant::now() >= barrier_deadline {
            let missing: Vec<u16> = (0..driver.n).filter(|i| *i != driver.self_index && !seen.contains(i)).collect();
            return Err(DriverError::Protocol(format!(
                "connection barrier timed out: nothing from peers {missing:?}{}",
                failures.describe()
            )));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // A peer still in its own barrier needs our HELLO too (our round 1 also counts).
    for _ in 0..3 {
        crate::wire::note_barrier_send(&mut failures, transport.broadcast(&hello));
        while let Ok(Some(msg)) = transport.poll() {
            take(msg, &mut seen, &mut early);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(early)
}

/// The last step of a dual DKG: every member says which key it finished with, and nobody
/// keeps the result unless all `n` finished with the same one. The protocols themselves
/// only tell a member about its own outcome — Pgw round 1 is a plain send-to-each, so one
/// member can leave others with different Pgw keys — and a key held by fewer than all `n`
/// has no member to spare.
///
/// Each claim is signed with the member's transport key ([`key_cert_message`]), so the
/// claims together are a [`KeyCertificate`]: proof, checkable by anyone holding the
/// committee consensus selected, that this committee and no one else made this key.
///
/// Each member re-broadcasts its claim until it has every peer's: a peer still finishing
/// the protocol drops frames that are not its own, so a claim sent once could be lost.
#[allow(clippy::too_many_arguments)]
pub fn confirm_key<T: SessionTransport>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    pgw: &[u8; 32],
    pevm: &[u8; 33],
    signer: &dyn crate::wire_auth::MsgSigner,
    ed: &dyn crate::wire_auth::Ed25519,
    transport: &mut T,
    timeout: Duration,
) -> Result<KeyCertificate, DriverError> {
    let n = committee.members.len() as u16;
    let tag = crate::committee::execution_id(
        b"beldex-dkg-confirm-v1",
        &[&committee.identity_bytes(), &key_generation.to_le_bytes()],
    );
    let message = key_cert_message(committee, key_generation, pgw, pevm);
    let mine = crate::coordinator::sha256(&message);
    let own_sig = signer.sign(&message).map_err(|e| DriverError::Protocol(format!("sign the key confirmation: {e}")))?;
    let mut body = mine.to_vec();
    body.extend_from_slice(&own_sig);
    let claim = WireMsg {
        leg: Leg::Pevm,
        epoch: committee.epoch,
        payload_hash: tag,
        attempt: 0,
        from: self_index,
        body: SessionMsg::Round(body),
    };
    let mut failures = crate::wire::BarrierSendFailures::default();
    let mut sigs: BTreeMap<u16, [u8; 64]> = BTreeMap::new();
    sigs.insert(self_index, own_sig);
    let take = |msg: WireMsg, sigs: &mut BTreeMap<u16, [u8; 64]>| -> Result<(), DriverError> {
        if msg.leg != Leg::Pevm || msg.epoch != committee.epoch || msg.payload_hash != tag || msg.from == self_index {
            return Ok(());
        }
        match &msg.body {
            SessionMsg::Round(p) if p.len() == 96 && p[..32] == mine[..] => {
                let sig: [u8; 64] = p[32..].try_into().expect("checked length");
                let signed = committee.signer_key(msg.from as usize).is_some_and(|k| ed.verify(&sig, &message, &k));
                if !signed {
                    return Err(DriverError::Protocol(format!(
                        "member {}'s confirmation is not signed with its committee key",
                        msg.from
                    )));
                }
                sigs.insert(msg.from, sig);
                Ok(())
            }
            SessionMsg::Round(_) => Err(DriverError::Protocol(format!(
                "member {} finished with a different key — not one key",
                msg.from
            ))),
            _ => Ok(()),
        }
    };
    let deadline = Instant::now() + timeout.min(Duration::from_secs(120));
    loop {
        crate::wire::note_barrier_send(&mut failures, transport.broadcast(&claim));
        while let Ok(Some(msg)) = transport.poll() {
            take(msg, &mut sigs)?;
        }
        if sigs.len() as u16 >= n {
            break;
        }
        if Instant::now() >= deadline {
            let missing: Vec<u16> = (0..n).filter(|i| !sigs.contains_key(i)).collect();
            return Err(DriverError::Protocol(format!(
                "key confirmation timed out: no confirmation from members {missing:?}{}",
                failures.describe()
            )));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // A peer still waiting needs our claim too; ours may have been dropped while it finished.
    for _ in 0..20 {
        crate::wire::note_barrier_send(&mut failures, transport.broadcast(&claim));
        while let Ok(Some(msg)) = transport.poll() {
            take(msg, &mut sigs)?;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(KeyCertificate {
        epoch: committee.epoch,
        height: committee.height,
        key_generation,
        pgw: *pgw,
        pevm: *pevm,
        sigs: sigs.into_iter().collect(),
    })
}

/// What every member of a committee signs for the key it made: the committee (its epoch
/// and members), the run, and both group keys.
pub fn key_cert_message(committee: &CommitteeView, key_generation: u32, pgw: &[u8; 32], pevm: &[u8; 33]) -> Vec<u8> {
    let mut m = b"beldex-bridge-keycert-v1".to_vec();
    m.extend_from_slice(&committee.identity_bytes());
    m.extend_from_slice(&key_generation.to_le_bytes());
    m.extend_from_slice(pgw);
    m.extend_from_slice(pevm);
    m
}

/// A committee's key with every member's signature on it ([`key_cert_message`]), made by
/// [`confirm_key`]. Each signature is checked against that member's `signer_ed25519`,
/// which consensus publishes, so the outgoing committee can tell the key it is asked to
/// hand the bridge to is the one the selected committee made — not one someone else did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCertificate {
    pub epoch: u64,
    /// The committee's selection height, to fetch it again (`bridge.committee` at it).
    pub height: u64,
    pub key_generation: u32,
    pub pgw: [u8; 32],
    pub pevm: [u8; 33],
    /// One per member, by committee index.
    pub sigs: Vec<(u16, [u8; 64])>,
}

impl KeyCertificate {
    const HEADER: &'static str = "beldex-bridge-keycert-v1";

    /// One `name value` per line; a `sig <index> <hex>` line per member.
    pub fn to_text(&self) -> String {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut s = format!(
            "{}\nepoch {}\nheight {}\nkey_generation {}\npgw {}\npevm {}\n",
            Self::HEADER, self.epoch, self.height, self.key_generation, hex(&self.pgw), hex(&self.pevm)
        );
        for (i, sig) in &self.sigs {
            s.push_str(&format!("sig {i} {}\n", hex(sig)));
        }
        s
    }

    pub fn from_text(text: &str) -> Result<KeyCertificate, String> {
        fn unhex<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
            let b: Option<Vec<u8>> =
                (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
            b.filter(|b| b.len() == N && s.len() == 2 * N)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("{what}: not {N} bytes of hex"))
        }
        let mut lines = text.lines();
        if lines.next() != Some(Self::HEADER) {
            return Err(format!("not a key certificate (no {} line)", Self::HEADER));
        }
        let (mut epoch, mut height, mut generation, mut pgw, mut pevm) = (None, None, None, None, None);
        let mut sigs = Vec::new();
        for line in lines.filter(|l| !l.trim().is_empty()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let num = |v: &str| v.parse::<u64>().map_err(|_| format!("bad number in `{line}`"));
            match parts.as_slice() {
                ["epoch", v] => epoch = Some(num(v)?),
                ["height", v] => height = Some(num(v)?),
                ["key_generation", v] => generation = Some(num(v)? as u32),
                ["pgw", v] => pgw = Some(unhex::<32>(v, "pgw")?),
                ["pevm", v] => pevm = Some(unhex::<33>(v, "pevm")?),
                ["sig", i, v] => sigs.push((num(i)? as u16, unhex::<64>(v, "sig")?)),
                _ => return Err(format!("unexpected line `{line}`")),
            }
        }
        Ok(KeyCertificate {
            epoch: epoch.ok_or("no epoch")?,
            height: height.ok_or("no height")?,
            key_generation: generation.ok_or("no key_generation")?,
            pgw: pgw.ok_or("no pgw")?,
            pevm: pevm.ok_or("no pevm")?,
            sigs,
        })
    }

    /// Whether this is `committee`'s key: the same epoch, and a valid signature from every
    /// one of its members — not a threshold of them, the same rule as [`confirm_key`].
    pub fn verify(&self, committee: &CommitteeView, ed: &dyn crate::wire_auth::Ed25519) -> Result<(), String> {
        if committee.epoch != self.epoch {
            return Err(format!("certificate is for epoch {}, the committee is epoch {}", self.epoch, committee.epoch));
        }
        let message = key_cert_message(committee, self.key_generation, &self.pgw, &self.pevm);
        let mut seen = BTreeSet::new();
        for (i, sig) in &self.sigs {
            let key = committee.signer_key(*i as usize).ok_or_else(|| format!("no member {i} with a signer key"))?;
            if !seen.insert(*i) {
                return Err(format!("two signatures for member {i}"));
            }
            if !ed.verify(sig, &message, &key) {
                return Err(format!("member {i}'s signature does not verify"));
            }
        }
        let n = committee.members.len() as u16;
        let missing: Vec<u16> = (0..n).filter(|i| !seen.contains(i)).collect();
        if !missing.is_empty() {
            return Err(format!("no signature from members {missing:?}"));
        }
        Ok(())
    }
}

/// Send a step's frames. Each round package goes out once, so every one must arrive:
/// see [`send_round`].
pub(crate) fn send_all<T: SessionTransport>(
    transport: &mut T,
    outs: Vec<Outbound>,
    deadline: Instant,
) -> Result<(), DriverError> {
    for o in outs {
        match o {
            Outbound::Broadcast(m) => send_round(transport, "dkg", crate::wire::Dest::All, &m, deadline)?,
            Outbound::To(idx, m) => send_round(transport, "dkg", crate::wire::Dest::One(idx), &m, deadline)?,
        }
    }
    Ok(())
}

/// Live-mesh assembly: build the curve-authenticated, message-authenticated OMQ
/// transport from the committee (for each member's `signer_ed25519`) plus this
/// node's mesh identity and the peer transport address book, then run the DKG.
///
/// The transport-auth keys (`signer_ed25519`) come from **consensus** (the
/// committee view), never from the peers file — the peers file supplies only the
/// network reachability (endpoint + curve key). Built when both the socket mesh
/// (`omq-mesh`) and libsodium (`tss-integration`) are present, i.e. the `live-dkg`
/// feature.
#[cfg(feature = "omq-mesh")]
pub mod live {
    use super::*;
    use crate::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
    use crate::wire_auth::{LibsodiumEd25519, LibsodiumSigner};

    /// This node's mesh identity: where it listens, its curve (channel) keypair,
    /// and its libsodium ed25519 transport-signing secret (message auth, S4).
    pub struct MeshIdentity {
        pub listen_endpoint: String,
        pub curve_secret: [u8; 32],
        pub curve_public: [u8; 32],
        pub ed25519_secret: [u8; 64],
    }

    /// A peer's network reachability (the daemon peer-address query will provide
    /// this in production; today an operator-supplied peers file does).
    pub struct PeerTransportAddr {
        pub index: u16,
        pub endpoint: String,
        pub curve_pubkey: [u8; 32],
    }

    /// Assemble the curve+message-authenticated OMQ mesh for one node: bind the
    /// listener, dial the peers, and attach the S4 message-auth context (each
    /// peer's `signer_ed25519` taken from **consensus**, not the peers file).
    /// Shared by both DKG legs (FROST here, cggmp21 in [`crate::cggmp21_driver`]).
    ///
    /// `use_curve` toggles the ZMQ CURVE channel: `true` encrypts + pins by x25519
    /// key; `false` runs plain sockets (libzmq without CURVE). Per-message ed25519
    /// authentication (S4) is always on either way.
    pub fn assemble_mesh(
        committee: &CommitteeView,
        self_index: u16,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
    ) -> Result<OmqPeerTransport, DriverError> {
        let mut mesh_peers = Vec::with_capacity(peers.len());
        for p in peers {
            let signer_ed25519 = committee
                .signer_key(p.index as usize)
                .ok_or(DriverError::BadCommittee)?;
            mesh_peers.push(PeerAddr {
                index: p.index,
                endpoint: p.endpoint.clone(),
                curve_pubkey: p.curve_pubkey,
                signer_ed25519,
            });
        }

        let mesh_cfg = OmqMeshConfig {
            self_index,
            listen_endpoint: identity.listen_endpoint.clone(),
            use_curve,
            self_curve_secret: identity.curve_secret,
            self_curve_public: identity.curve_public,
            peers: mesh_peers,
        };
        let transport = OmqPeerTransport::bind(&mesh_cfg)
            .map_err(|e| DriverError::Transport(format!("mesh bind: {e:?}")))?;
        let auth = MeshAuth::from_committee(
            Box::new(LibsodiumSigner { sk64: identity.ed25519_secret }),
            Box::new(LibsodiumEd25519),
            committee,
        )
        .ok_or_else(|| DriverError::Transport("committee has no signer_keys".into()))?;
        Ok(transport.with_auth(auth))
    }

    /// Assemble the authenticated mesh and run the FROST (`Pgw`) DKG to completion.
    #[allow(clippy::too_many_arguments)]
    pub fn run_live<S, R>(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        store: &mut S,
        rng: &mut R,
        timeout: Duration,
    ) -> Result<[u8; 32], DriverError>
    where
        S: ShareStore,
        R: RngCore + CryptoRng,
    {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        super::run_over_transport(
            committee,
            self_index,
            key_generation,
            &mut transport,
            store,
            rng,
            timeout,
        )
    }

    /// Like [`run_live`], but returns the completed key material `(group_vk,
    /// key_package_blob, pubkey_package_blob)` for the caller to persist (so a later
    /// `sign` invocation can load it), instead of storing into a [`ShareStore`].
    #[allow(clippy::too_many_arguments)]
    pub fn run_live_capture<R>(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        rng: &mut R,
        timeout: Duration,
    ) -> Result<([u8; 32], Vec<u8>, Vec<u8>), DriverError>
    where
        R: RngCore + CryptoRng,
    {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        super::run_over_transport_capture(
            committee,
            self_index,
            key_generation,
            &mut transport,
            rng,
            timeout,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_verify_consensus, ensure_init};
    use crate::share_store::MemoryShareStore;
    use std::collections::VecDeque;

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
            round_height: 0,
        }
    }

    /// An in-process message bus: one inbox per node. Routing mirrors the real
    /// transport (Broadcast → every other node; To(idx) → that node), so the
    /// driver's step logic is exercised exactly as it would be over sockets.
    struct Bus {
        inboxes: Vec<VecDeque<WireMsg>>,
    }
    impl Bus {
        fn new(n: u16) -> Bus {
            Bus { inboxes: (0..n).map(|_| VecDeque::new()).collect() }
        }
        fn route(&mut self, from: u16, outs: Vec<Outbound>) {
            for o in outs {
                match o {
                    Outbound::Broadcast(m) => {
                        for (i, inbox) in self.inboxes.iter_mut().enumerate() {
                            if i as u16 != from {
                                inbox.push_back(m.clone());
                            }
                        }
                    }
                    Outbound::To(idx, m) => self.inboxes[idx as usize].push_back(m),
                }
            }
        }
    }

    /// Drive a real `n`-party FROST DKG through the driver over the in-process
    /// bus, then verify the group key + a threshold signature under libsodium.
    fn run_dkg(n: u16, t: u16) {
        ensure_init().unwrap();
        let c = committee(n, t);
        let mut rng = rand::rngs::OsRng;

        // begin() for every node; seed the bus with the round-1 broadcasts.
        let mut drivers = Vec::new();
        let mut bus = Bus::new(n);
        for i in 0..n {
            let (d, first) = FrostDkgDriver::begin(&c, i, 0, &mut rng).unwrap();
            bus.route(i, first);
            drivers.push(d);
        }

        // Pump until all nodes complete: drain each inbox, feed the driver, route
        // its responses. DKG progress is monotonic, so this converges.
        let mut guard = 0;
        while !drivers.iter().all(|d| d.is_complete()) {
            for i in 0..n as usize {
                while let Some(msg) = bus.inboxes[i].pop_front() {
                    let outs = drivers[i].on_wire(&msg, &mut rng).unwrap();
                    bus.route(i as u16, outs);
                }
            }
            guard += 1;
            assert!(guard < 100, "DKG did not converge");
        }

        // Every node derived the identical group key (the gateway owner_key).
        let vk0 = drivers[0].group_pubkey().unwrap();
        assert!(drivers.iter().all(|d| d.group_pubkey() == Some(vk0)));

        // Each node stored its own share at the key generation (S1).
        for (i, d) in drivers.iter().enumerate() {
            let mut store = MemoryShareStore::new();
            d.store_share(&mut store);
            let (ver, blob) = store.get_latest("pgw.share").expect("share stored");
            assert_eq!(ver, 0);
            assert!(!blob.is_empty(), "node {i} stored an empty share");
        }

        // The DKG'd key signs an ordinary ed25519 signature consensus accepts.
        // Reconstruct KeyPackages from the stored blobs and run a t-of-n sign.
        let mut key_packages = BTreeMap::new();
        for (i, d) in drivers.iter().enumerate() {
            let mut store = MemoryShareStore::new();
            d.store_share(&mut store);
            let (_v, blob) = store.get_latest("pgw.share").unwrap();
            let kp = frost::keys::KeyPackage::deserialize(&blob).expect("deserialize kp");
            let id: Id = ((i as u16) + 1).try_into().unwrap();
            key_packages.insert(id, kp);
        }

        // Build a PublicKeyPackage from the individual verifying shares.
        let pubkey_package = public_key_package_from(&key_packages);

        let message = b"GW_INPUT_SIG || genesis || tx_prefix_hash (live-dkg test)";
        let sig = sign_t_of_n(&key_packages, &pubkey_package, t, message);
        assert!(
            ed25519_verify_consensus(&sig, message, &vk0),
            "{t}-of-{n}: libsodium rejected a signature under the mesh-DKG'd key"
        );
    }

    /// Rebuild the public key package from the members' verifying shares + the
    /// agreed group key, so a signature can be aggregated in the test.
    fn public_key_package_from(
        key_packages: &BTreeMap<Id, frost::keys::KeyPackage>,
    ) -> frost::keys::PublicKeyPackage {
        // `.clone()` works whether these frost types are Copy or only Clone.
        let verifying_shares: BTreeMap<Id, _> = key_packages
            .iter()
            .map(|(id, kp)| (*id, kp.verifying_share().clone()))
            .collect();
        let group_vk = key_packages.values().next().unwrap().verifying_key().clone();
        frost::keys::PublicKeyPackage::new(verifying_shares, group_vk)
    }

    fn sign_t_of_n(
        key_packages: &BTreeMap<Id, frost::keys::KeyPackage>,
        pubkey_package: &frost::keys::PublicKeyPackage,
        t: u16,
        message: &[u8],
    ) -> [u8; 64] {
        let mut rng = rand::rngs::OsRng;
        let signers: Vec<Id> = key_packages.keys().copied().take(t as usize).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for sid in &signers {
            let (n, c) = frost::round1::commit(key_packages[sid].signing_share(), &mut rng);
            nonces.insert(*sid, n);
            commitments.insert(*sid, c);
        }
        let signing_package = frost::SigningPackage::new(commitments, message);
        let mut shares = BTreeMap::new();
        for sid in &signers {
            shares.insert(
                *sid,
                frost::round2::sign(&signing_package, &nonces[sid], &key_packages[sid]).unwrap(),
            );
        }
        let sig = frost::aggregate(&signing_package, &shares, pubkey_package).unwrap();
        let v = sig.serialize().unwrap();
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn four_of_six_dkg_over_the_bus_is_consensus_verifiable() {
        run_dkg(6, 4); // the devnet committee shape
    }

    #[test]
    fn small_committees_dkg_over_the_bus() {
        run_dkg(3, 2);
        run_dkg(5, 3);
    }

    /// Full real-transport DKG on one machine, **no devnet / no beldexd**: N signer
    /// meshes over real ZMQ sockets on localhost, each authenticating peers'
    /// messages against a synthetic committee's `signer_keys` (S4, real libsodium
    /// ed25519), running the driver to completion. `use_curve` toggles the CURVE
    /// channel — the `curve` test needs a libzmq built with CURVE; the `plain`
    /// test runs the identical flow without channel encryption (still exercising
    /// the real sockets + the security-critical per-message auth) so it works on
    /// any libzmq. Exercises everything except the committee read.
    #[cfg(feature = "omq-mesh")]
    fn socket_dkg_harness(use_curve: bool, base_port: u16, stagger: std::time::Duration, absent: Option<u16>) {
        use crate::committee::CommitteeView;
        use crate::ffi::ed25519_keypair;
        use crate::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
        use crate::share_store::MemoryShareStore;
        use crate::wire_auth::{LibsodiumEd25519, LibsodiumSigner};
        use std::sync::mpsc;
        use std::time::Duration;

        ensure_init().unwrap();
        if use_curve && zmq::CurveKeyPair::new().is_err() {
            eprintln!("SKIP: linked libzmq has no CURVE support (rebuild libzmq with libsodium)");
            return;
        }

        let (n, t) = (6u16, 4u16);

        // Per-node identities: ed25519 (message auth, S4) always; curve (channel)
        // only when CURVE is in use (else zeros, which the plain path ignores).
        let mut ed_pk = Vec::new();
        let mut ed_sk = Vec::new();
        let mut cv_pk = Vec::new();
        let mut cv_sk = Vec::new();
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            ed_pk.push(pk);
            ed_sk.push(sk);
            if use_curve {
                let kp = zmq::CurveKeyPair::new().unwrap();
                cv_pk.push(kp.public_key);
                cv_sk.push(kp.secret_key);
            } else {
                cv_pk.push([0u8; 32]);
                cv_sk.push([0u8; 32]);
            }
        }

        // Synthetic committee: dummy MN pubkeys; signer_keys are the ed25519 pks
        // (what the mesh authenticates each peer's `from` against).
        let committee = CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: ed_pk.clone(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
            round_height: 0,
        };

        // A run missing a member stops at the connection barrier, which is bounded by the
        // run's timeout: keep that short so the test does not wait out a whole DKG.
        let run_timeout = match absent {
            Some(_) => Duration::from_secs(5),
            None => Duration::from_secs(30) + stagger * n as u32,
        };
        let started = std::time::Instant::now();
        let (tx, rx) = mpsc::channel();
        let mut handles = Vec::new();
        for i in 0..n {
            if absent == Some(i) {
                continue;
            }
            let committee = committee.clone();
            let ed_pk = ed_pk.clone();
            let cv_pk = cv_pk.clone();
            let self_sk = ed_sk[i as usize];
            let self_cv_sk = cv_sk[i as usize];
            let self_cv_pk = cv_pk[i as usize];
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                let ep = |p: u16| format!("tcp://127.0.0.1:{p}");
                let peers: Vec<PeerAddr> = (0..n)
                    .filter(|j| *j != i)
                    .map(|j| PeerAddr {
                        index: j,
                        endpoint: ep(base_port + j),
                        curve_pubkey: cv_pk[j as usize],
                        signer_ed25519: ed_pk[j as usize],
                    })
                    .collect();
                let cfg = OmqMeshConfig {
                    self_index: i,
                    listen_endpoint: ep(base_port + i),
                    use_curve,
                    self_curve_secret: self_cv_sk,
                    self_curve_public: self_cv_pk,
                    peers,
                };
                let transport = OmqPeerTransport::bind(&cfg).expect("bind mesh");
                let auth = MeshAuth::new(
                    Box::new(LibsodiumSigner { sk64: self_sk }),
                    Box::new(LibsodiumEd25519),
                    committee.auth_members(),
                );
                let mut transport = transport.with_auth(auth);
                let mut store = MemoryShareStore::new();
                let mut rng = rand::rngs::OsRng;
                // Let every node bind + connect before the first round-1 sends.
                std::thread::sleep(Duration::from_millis(800) + stagger * i as u32);
                let vk = run_over_transport(
                    &committee, i, 0, &mut transport, &mut store, &mut rng,
                    run_timeout,
                );
                tx.send((i, vk)).unwrap();
            }));
        }
        drop(tx);

        if let Some(a) = absent {
            // Every present member gives up at the barrier, naming the absent one, instead
            // of waiting out its timeout for round packages that will never come.
            for _ in 1..n {
                let (i, vk) = rx.recv().unwrap();
                match vk {
                    Err(DriverError::Protocol(m)) if m.contains(&format!("[{a}]")) => {}
                    other => panic!("node {i}: expected a barrier failure naming peer {a}, got {other:?}"),
                }
            }
            for h in handles {
                h.join().unwrap();
            }
            assert!(started.elapsed() < Duration::from_secs(20), "the barrier did not fail fast");
            return;
        }

        let mut vks = Vec::new();
        for _ in 0..n {
            let (i, vk) = rx.recv().unwrap();
            vks.push(vk.unwrap_or_else(|e| panic!("node {i} dkg failed: {e:?}")));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Every node completed the DKG over real sockets and agrees on the key.
        assert!(vks.iter().all(|v| *v == vks[0]), "nodes disagree on the group key");
        eprintln!(
            "OK: 6-node DKG over real {} sockets agreed on group key {}",
            if use_curve { "CURVE" } else { "plain" },
            vks[0].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
    }

    /// Real sockets **with** CURVE channel auth (needs libzmq built with CURVE).
    ///   cargo test -p beldex-bridge-signer --features live-dkg -- --ignored --nocapture dkg_over_real_curve_sockets
    #[cfg(feature = "omq-mesh")]
    #[test]
    #[ignore = "binds real ZMQ CURVE sockets on localhost"]
    fn dkg_over_real_curve_sockets() {
        socket_dkg_harness(true, 55900, std::time::Duration::ZERO, None);
    }

    /// Real sockets **without** CURVE (works on any libzmq): still exercises the
    /// live sockets + per-message ed25519 authentication — the S4 security layer.
    ///   cargo test -p beldex-bridge-signer --features live-dkg -- --ignored --nocapture dkg_over_real_plain_sockets
    #[cfg(feature = "omq-mesh")]
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn dkg_over_real_plain_sockets() {
        socket_dkg_harness(false, 55920, std::time::Duration::ZERO, None);
    }

    /// Members that start the protocol seconds apart, as automatic starts on separate hosts
    /// do: the last starts 15s after the first.
    ///   cargo test -p beldex-bridge-signer --features live-dkg -- --ignored --nocapture dkg_over_sockets_with_members_starting_apart
    #[cfg(feature = "omq-mesh")]
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn dkg_over_sockets_with_members_starting_apart() {
        socket_dkg_harness(false, 55940, std::time::Duration::from_secs(3), None);
    }

    /// One member never starts: the others stop within seconds and name it, so the next
    /// attempt is not lost waiting out a whole DKG timeout.
    ///   cargo test -p beldex-bridge-signer --features live-dkg -- --ignored --nocapture dkg_over_sockets_stops_fast_without_a_member
    #[cfg(feature = "omq-mesh")]
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn dkg_over_sockets_stops_fast_without_a_member() {
        socket_dkg_harness(false, 55960, std::time::Duration::ZERO, Some(5));
    }

    /// A bus shared across threads, for drivers that run concurrently ([`confirm_key`]).
    #[derive(Clone)]
    struct SharedBus(std::sync::Arc<Vec<std::sync::Mutex<VecDeque<WireMsg>>>>, u16);
    impl SessionTransport for SharedBus {
        fn broadcast(&mut self, msg: &WireMsg) -> Result<(), crate::wire::MeshError> {
            for (i, inbox) in self.0.iter().enumerate() {
                if i as u16 != self.1 {
                    inbox.lock().unwrap().push_back(msg.clone());
                }
            }
            Ok(())
        }
        fn send_to(&mut self, peer: u16, msg: &WireMsg) -> Result<(), crate::wire::MeshError> {
            self.0[peer as usize].lock().unwrap().push_back(msg.clone());
            Ok(())
        }
        fn poll(&mut self) -> Result<Option<WireMsg>, crate::wire::MeshError> {
            Ok(self.0[self.1 as usize].lock().unwrap().pop_front())
        }
    }

    /// A stand-in transport key: a "signature" is H(key ‖ msg) ‖ H(msg ‖ key), so it binds
    /// both and cannot be made without the key's bytes. Real ed25519 is tested in `ffi.rs`.
    struct TestKey([u8; 32]);
    fn test_sig(key: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        let mut s = [0u8; 64];
        s[..32].copy_from_slice(&crate::coordinator::sha256(&[&key[..], msg].concat()));
        s[32..].copy_from_slice(&crate::coordinator::sha256(&[msg, &key[..]].concat()));
        s
    }
    impl crate::wire_auth::MsgSigner for TestKey {
        fn sign(&self, msg: &[u8]) -> Result<[u8; 64], &'static str> {
            Ok(test_sig(&self.0, msg))
        }
    }
    struct TestEd;
    impl crate::wire_auth::Ed25519 for TestEd {
        fn verify(&self, sig: &[u8; 64], msg: &[u8], pubkey: &[u8; 32]) -> bool {
            *sig == test_sig(pubkey, msg)
        }
    }

    fn signed_committee(n: u16) -> CommitteeView {
        let mut c = committee(n, n - 1);
        c.signer_keys = (0..n).map(|i| [100 + i as u8; 32]).collect();
        c
    }

    /// Run [`confirm_key`] on every member, member `i` claiming `keys[i]` (`None` = absent);
    /// member `forger` signs with a key that is not its committee key.
    fn confirm_all(keys: &[Option<&'static str>], forger: Option<usize>) -> Vec<Option<Result<KeyCertificate, DriverError>>> {
        let n = keys.len() as u16;
        let c = signed_committee(n);
        let inboxes = std::sync::Arc::new((0..n).map(|_| std::sync::Mutex::new(VecDeque::new())).collect());
        let handles: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let (c, mut bus, key) = (c.clone(), SharedBus(std::sync::Arc::clone(&inboxes), i as u16), *key);
                let signer = TestKey(if forger == Some(i) { [0xEE; 32] } else { c.signer_keys[i] });
                std::thread::spawn(move || {
                    key.map(|k| {
                        let pgw = crate::coordinator::sha256(k.as_bytes());
                        confirm_key(&c, i as u16, 1, &pgw, &[2; 33], &signer, &TestEd, &mut bus, Duration::from_secs(3))
                    })
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    }

    #[test]
    fn every_member_keeps_the_key_only_when_all_finished_with_it() {
        let all = confirm_all(&[Some("K"), Some("K"), Some("K"), Some("K")], None);
        assert!(all.iter().all(|r| matches!(r, Some(Ok(_)))), "{all:?}");

        // One member with a different key: everyone else refuses, naming it.
        let split = confirm_all(&[Some("K"), Some("K"), Some("X"), Some("K")], None);
        for (i, r) in split.iter().enumerate() {
            match r {
                Some(Err(DriverError::Protocol(m))) if i != 2 => assert!(m.contains("member 2"), "{m}"),
                Some(Err(DriverError::Protocol(_))) => {}
                other => panic!("member {i}: {other:?}"),
            }
        }

        // One member never confirms: the rest give up, naming it.
        let absent = confirm_all(&[Some("K"), None, Some("K"), Some("K")], None);
        for r in absent.iter().flatten() {
            match r {
                Err(DriverError::Protocol(m)) => assert!(m.contains("[1]"), "{m}"),
                other => panic!("{other:?}"),
            }
        }

        // One member signs with a key that is not its committee key: the rest refuse it.
        let forged = confirm_all(&[Some("K"), Some("K"), Some("K"), Some("K")], Some(3));
        for (i, r) in forged.iter().enumerate().filter(|(i, _)| *i != 3) {
            match r {
                Some(Err(DriverError::Protocol(m))) => assert!(m.contains("member 3"), "member {i}: {m}"),
                other => panic!("member {i}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_certificate_proves_the_whole_committee_made_the_key() {
        let all = confirm_all(&[Some("K"), Some("K"), Some("K"), Some("K")], None);
        let certs: Vec<KeyCertificate> = all.into_iter().map(|r| r.unwrap().unwrap()).collect();
        // Every member ends with the same certificate, and it reads back from its file form.
        assert!(certs.windows(2).all(|w| w[0] == w[1]));
        let cert = KeyCertificate::from_text(&certs[0].to_text()).unwrap();
        assert_eq!(cert, certs[0]);
        assert_eq!(cert.sigs.len(), 4);

        let c = signed_committee(4);
        cert.verify(&c, &TestEd).unwrap();

        // Someone else's key under these signatures does not verify.
        let mut other = cert.clone();
        other.pevm = [3; 33];
        assert!(other.verify(&c, &TestEd).unwrap_err().contains("does not verify"));
        // Neither does one with a member's signature missing...
        let mut short = cert.clone();
        short.sigs.remove(2);
        assert!(short.verify(&c, &TestEd).unwrap_err().contains("[2]"));
        // ...nor one checked against a different committee.
        let mut later = signed_committee(4);
        later.epoch += 1;
        assert!(cert.verify(&later, &TestEd).is_err());
    }

    /// A run that fails after a peer went over its frame budget says which peer.
    #[test]
    fn a_failed_run_names_the_peer_that_flooded_it() {
        struct Flood(u32);
        impl SessionTransport for Flood {
            fn broadcast(&mut self, _m: &WireMsg) -> Result<(), crate::wire::MeshError> { Ok(()) }
            fn send_to(&mut self, _p: u16, _m: &WireMsg) -> Result<(), crate::wire::MeshError> { Ok(()) }
            fn poll(&mut self) -> Result<Option<WireMsg>, crate::wire::MeshError> {
                if self.0 == 0 { return Ok(None) }
                self.0 -= 1;
                Ok(Some(WireMsg { leg: Leg::Pgw, epoch: 2, payload_hash: [7; 32], attempt: 0, from: 3, body: SessionMsg::Ack }))
            }
        }
        let mut t = Flood(crate::wire::MAX_FRAMES_PER_PEER_PER_RUN + 10);
        let r: Result<(), DriverError> = with_frame_budget(&mut t, |b| {
            while b.poll().unwrap().is_some() {}
            Err(DriverError::Timeout)
        });
        match r {
            Err(DriverError::Protocol(m)) => assert!(m.contains("peer 3 sent more than"), "{m}"),
            other => panic!("expected the flooder named, got {other:?}"),
        }
        // Without a flood, the run's own error comes through unchanged.
        let mut quiet = Flood(5);
        let r: Result<(), DriverError> = with_frame_budget(&mut quiet, |_| Err(DriverError::Timeout));
        assert_eq!(r, Err(DriverError::Timeout));
    }
}

//! Rotation-ack attestation — signer side (**H.6.3**).
//!
//! The wBDX contract's mint authority (`currentSigner`) is repointed to a new committee's
//! fresh-DKG address by a self-authorizing hand-off (`rotateSigner` → `activateRotation`,
//! or the admin break-glass), each emitting a `Rotated(newSigner, newKeyEpoch)` event on
//! chain (see `bridge-contract/src/WrappedBDX.sol`). An EVM log is not natively visible to
//! Beldex consensus, so "L1 observed the rotation" is a **committee attestation** with the
//! identical structure as the Phase F slash report ([`crate::slash`]): a threshold of the
//! **committee active at observation time** independently see the event on their own EVM
//! RPCs and co-sign a canonical, genesis-bound statement; `beldexd` verifies only the
//! ≥ `t+1` ed25519 signatures against that epoch's committee — never trusting one node's
//! claim to have seen a log.
//!
//! L1 uses these attestations to gate an outgoing seat's **bond release** (H.6.3): a bond
//! is released only once every registered chain has rotated **past** the key epoch that
//! chain stood at when the seat requested unbond — so signing in your successor becomes a
//! precondition for reclaiming your 100k bond.
//!
//! The signed bytes are the **objective, epoch-independent fact**: the chain, the wBDX
//! contract, the new key epoch and signer, and the exact `Rotated` log (transaction and
//! log index) — unlike a slash report, which is inherently session/epoch-specific. Members
//! only pool signatures over the same event of the same contract, consensus holds every
//! ack for a chain to the contract its first ack named, and anyone can look the cited log
//! up on the EVM chain. The L1 committee `epoch` that observed it rides alongside as an
//! unsigned resolver hint (it only selects which committee's keys the verifier checks; a
//! wrong epoch simply yields the wrong keys and fails). Consensus counts only observers
//! whose bridge bond is still at stake (not released, not slashed), and accepts only the
//! next key epoch for a chain, so a replayed ack is a no-op.
//!
//! Built under `tss-integration` (libsodium ed25519), mirroring [`crate::slash`].

use crate::committee::CommitteeView;
use crate::ffi::{ed25519_sign_detached, ed25519_verify_consensus};

/// Domain tag for the rotation-ack signature (S6). MUST match the C++
/// `hashkey::BRIDGE_ROTATION_ACK`.
pub const ROTATION_ACK_DOMAIN: &[u8] = b"bridge_rotation_ack_v2";

/// The ack layout these bytes describe. MUST match the C++
/// `tx_extra_bridge_rotation_ack::CURRENT_VERSION`; consensus accepts no other.
pub const ROTATION_ACK_VERSION: u8 = 1;

/// The objective on-chain fact an ack attests: `contract` on chain `chain_id` emitted
/// `Rotated(new_signer, key_epoch)` in transaction `evm_txid` at log `log_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationAck {
    /// EVM chain id (the E.3 registry key).
    pub chain_id: u64,
    /// The wBDX proxy that emitted the event.
    pub contract: [u8; 20],
    /// The contract's new monotonic key epoch after the rotation.
    pub key_epoch: u64,
    /// The incoming `Pevm` address the contract now trusts as mint authority.
    pub new_signer: [u8; 20],
    /// The EVM transaction carrying the `Rotated` log, and that log's index.
    pub evm_txid: [u8; 32],
    pub log_index: u32,
}

impl RotationAck {
    /// The fact a finalized `Rotated` event states.
    #[cfg(feature = "evm-watcher")]
    pub fn from_event(ev: &crate::evm_watcher::RotationEvent) -> RotationAck {
        RotationAck {
            chain_id: ev.chain.0,
            contract: ev.contract,
            key_epoch: ev.key_epoch,
            new_signer: ev.new_signer,
            evm_txid: ev.evm_txid,
            log_index: ev.log_index,
        }
    }
}

impl RotationAck {
    /// The mesh routing key for this fact: `sha256` of its canonical bytes.
    ///
    /// Used as the wire `payload_hash`, so every member observing the same rotation
    /// independently produces the same key, and signatures for two different rotations
    /// can never be matched to each other.
    pub fn mesh_key(&self, genesis: &[u8; 32]) -> [u8; 32] {
        crate::coordinator::sha256(&self.canonical(genesis))
    }

    /// The canonical, **genesis-bound** bytes the observing quorum signs and `beldexd`
    /// verifies. Domain-separated (S6); the genesis binding prevents replay across
    /// networks/forks (S14). Epoch-independent — the fact is objective.
    ///
    /// Layout: `DOMAIN ‖ genesis(32) ‖ version(u8) ‖ chain_id(u64 LE) ‖ contract(20) ‖
    /// key_epoch(u64 LE) ‖ new_signer(20) ‖ evm_txid(32) ‖ log_index(u32 LE)`.
    pub fn canonical(&self, genesis: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(ROTATION_ACK_DOMAIN.len() + 32 + 1 + 8 + 20 + 8 + 20 + 32 + 4);
        v.extend_from_slice(ROTATION_ACK_DOMAIN);
        v.extend_from_slice(genesis);
        v.push(ROTATION_ACK_VERSION);
        v.extend_from_slice(&self.chain_id.to_le_bytes());
        v.extend_from_slice(&self.contract);
        v.extend_from_slice(&self.key_epoch.to_le_bytes());
        v.extend_from_slice(&self.new_signer);
        v.extend_from_slice(&self.evm_txid);
        v.extend_from_slice(&self.log_index.to_le_bytes());
        v
    }
}

/// A rotation ack co-signed by the observing committee (H.6.3). Each observer signs the
/// [`canonical`](RotationAck::canonical) bytes with its bridge-signer ed25519 key — the
/// same key consensus binds to it via `signer_keys` (S4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRotationAck {
    pub ack: RotationAck,
    /// The L1 committee epoch that observed + signed this (the verifier's resolver hint;
    /// **not** part of the signed canonical bytes).
    pub epoch: u64,
    /// `(committee_index, detached ed25519 signature)` per observer.
    pub observers: Vec<(u16, [u8; 64])>,
}

impl SignedRotationAck {
    /// Start an ack from an observed rotation (no signatures yet). `epoch` is the observing
    /// committee's L1 epoch.
    pub fn new(ack: RotationAck, epoch: u64) -> SignedRotationAck {
        SignedRotationAck { ack, epoch, observers: Vec::new() }
    }

    /// This node signs the ack with its bridge-signer ed25519 secret and adds itself as an
    /// observer.
    pub fn sign_as(
        &mut self,
        committee_index: u16,
        ed25519_sk64: &[u8; 64],
        genesis: &[u8; 32],
    ) -> Result<(), &'static str> {
        if self.observers.iter().any(|(i, _)| *i == committee_index) {
            return Ok(()); // already signed
        }
        let sig = ed25519_sign_detached(ed25519_sk64, &self.ack.canonical(genesis))?;
        self.observers.push((committee_index, sig));
        Ok(())
    }

    /// Absorb another member's signatures for the **same** fact.
    ///
    /// Members observe the rotation independently and each signs its own copy, so the
    /// threshold evidence is assembled by merging. Returns false if `other` attests a
    /// different fact — two different rotations must never have their signatures pooled,
    /// or the result would carry signatures over bytes nobody agreed on.
    ///
    /// Signatures are not verified here; [`verify`](Self::verify) is the gate, and it
    /// ignores anything that does not check out. Merging an unverified signature can
    /// therefore only waste space, never admit a bad ack.
    pub fn merge(&mut self, other: &SignedRotationAck) -> bool {
        if self.ack != other.ack {
            return false;
        }
        for (index, sig) in &other.observers {
            if !self.observers.iter().any(|(i, _)| i == index) {
                self.observers.push((*index, *sig));
            }
        }
        true
    }

    /// How many distinct committee members have signed, counting only signatures that
    /// actually verify — the same rule the daemon applies.
    pub fn valid_signature_count(&self, committee: &CommitteeView, genesis: &[u8; 32]) -> usize {
        let msg = self.ack.canonical(genesis);
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = 0usize;
        for (index, sig) in &self.observers {
            if !seen.insert(*index) {
                continue;
            }
            if let Some(pk) = committee.signer_key(*index as usize) {
                if ed25519_verify_consensus(sig, &msg, &pk) {
                    valid += 1;
                }
            }
        }
        valid
    }

    /// Verify the ack is admissible: co-signed by **≥ threshold distinct committee members**,
    /// each signature valid over the canonical fact under that member's consensus-published
    /// `signer_ed25519`. (`beldexd` re-runs this before advancing its observed key epoch.)
    pub fn verify(&self, committee: &CommitteeView, genesis: &[u8; 32]) -> bool {
        let msg = self.ack.canonical(genesis);
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = 0usize;
        for (index, sig) in &self.observers {
            if !seen.insert(*index) {
                continue; // duplicate observer
            }
            let Some(pk) = committee.signer_key(*index as usize) else {
                continue; // not a committee member with a published signer key
            };
            if ed25519_verify_consensus(sig, &msg, &pk) {
                valid += 1;
            }
        }
        valid >= committee.threshold
    }

    /// Serialize the ack into the JSON body `beldexd`'s `bridge.rotation_ack` OMQ intake
    /// expects. Observers are emitted **sorted and deduplicated by committee index** — the
    /// C++ verifier's canonical strictly-ascending form, while [`sign_as`](Self::sign_as)
    /// appends in arrival order.
    pub fn to_submission_json(&self) -> String {
        let mut observers: Vec<(u16, [u8; 64])> = self.observers.clone();
        observers.sort_by_key(|(i, _)| *i);
        observers.dedup_by_key(|(i, _)| *i);

        let hexs = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let hex64 = |b: &[u8; 64]| hexs(b);

        let entries: Vec<String> = observers
            .iter()
            .map(|(i, s)| format!(r#"{{"voter_index":{i},"signature":"{}"}}"#, hex64(s)))
            .collect();

        format!(
            concat!(
                r#"{{"version":{},"chain_id":{},"contract":"{}","key_epoch":{},"new_signer":"{}","#,
                r#""evm_txid":"{}","log_index":{},"epoch":{},"observers":[{}]}}"#
            ),
            ROTATION_ACK_VERSION,
            self.ack.chain_id,
            hexs(&self.ack.contract),
            self.ack.key_epoch,
            hexs(&self.ack.new_signer),
            hexs(&self.ack.evm_txid),
            self.ack.log_index,
            self.epoch,
            entries.join(","),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_keypair, ensure_init};

    fn committee_with_signer_keys(n: u16, t: u16) -> (CommitteeView, Vec<[u8; 64]>) {
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        let c = CommitteeView {
            epoch: 7,
            height: 840,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: pks,
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        };
        (c, sks)
    }

    fn sample_ack() -> RotationAck {
        RotationAck {
            chain_id: 42,
            contract: [0x22; 20],
            key_epoch: 8,
            new_signer: [0xCD; 20],
            evm_txid: [0xEE; 32],
            log_index: 3,
        }
    }

    #[test]
    fn quorum_signed_ack_verifies_and_needs_threshold() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let mut signed = SignedRotationAck::new(sample_ack(), committee.epoch);
        for i in [0u16, 1, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        assert!(!signed.verify(&committee, &genesis), "3 < threshold 4");

        signed.sign_as(4, &sks[4], &genesis).unwrap();
        assert!(signed.verify(&committee, &genesis));

        // Genesis binding: a signature over a different genesis (replay) is rejected.
        assert!(!signed.verify(&committee, &[0xff; 32]));
    }

    #[test]
    fn forged_observer_signature_is_rejected() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let mut signed = SignedRotationAck::new(sample_ack(), committee.epoch);
        for i in [0u16, 2, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        // Member 4 "observes" but signs with member 5's key → invalid under member 4's pub.
        let sig = ed25519_sign_detached(&sks[5], &signed.ack.canonical(&genesis)).unwrap();
        signed.observers.push((4, sig));
        assert!(!signed.verify(&committee, &genesis), "forged 4th signature does not count");
    }

    #[test]
    fn distinct_facts_produce_distinct_signed_bytes() {
        let genesis = [1u8; 32];
        let base = sample_ack().canonical(&genesis);
        // A different chain, key epoch, or signer must change the bytes (no cross-binding).
        let other_chain = RotationAck { chain_id: 43, ..sample_ack() }.canonical(&genesis);
        let other_epoch = RotationAck { key_epoch: 9, ..sample_ack() }.canonical(&genesis);
        let other_signer = RotationAck { new_signer: [0xEE; 20], ..sample_ack() }.canonical(&genesis);
        let other_contract = RotationAck { contract: [0x33; 20], ..sample_ack() }.canonical(&genesis);
        let other_tx = RotationAck { evm_txid: [0x01; 32], ..sample_ack() }.canonical(&genesis);
        let other_log = RotationAck { log_index: 4, ..sample_ack() }.canonical(&genesis);
        assert_ne!(base, other_chain);
        assert_ne!(base, other_epoch);
        assert_ne!(base, other_signer);
        assert_ne!(base, other_contract, "the contract is signed");
        assert_ne!(base, other_tx, "the cited transaction is signed");
        assert_ne!(base, other_log, "the cited log is signed");
        // Leads with the domain tag (S6).
        assert_eq!(&base[..ROTATION_ACK_DOMAIN.len()], ROTATION_ACK_DOMAIN);
    }

    /// The exact bytes a rotation ack signs, as the daemon builds them for mainnet. The C++
    /// test `GatewayBridgeRotation.rotation_ack_message_is_pinned` asserts the same hex, so
    /// the two cannot drift apart without one of them failing.
    #[test]
    fn canonical_bytes_match_the_daemon() {
        const PIN: &str = "6272696467655f726f746174696f6e5f61636b5f76326ea477622339f61c5fba036dc75c08b6efcf9ee09c108e5c5591fcc233d17b2001380000000000000022222222222222222222222222222222222222220700000000000000cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f04030201";
        let pin: Vec<u8> = (0..PIN.len()).step_by(2).map(|i| u8::from_str_radix(&PIN[i..i + 2], 16).unwrap()).collect();
        // The mainnet genesis binding sits right after the domain tag.
        let mut genesis = [0u8; 32];
        genesis.copy_from_slice(&pin[ROTATION_ACK_DOMAIN.len()..ROTATION_ACK_DOMAIN.len() + 32]);
        let mut evm_txid = [0u8; 32];
        for (i, b) in evm_txid.iter_mut().enumerate() {
            *b = i as u8;
        }
        let ack = RotationAck {
            chain_id: 56,
            contract: [0x22; 20],
            key_epoch: 7,
            new_signer: [0xCD; 20],
            evm_txid,
            log_index: 0x01020304,
        };
        assert_eq!(ack.canonical(&genesis), pin);
    }

    #[test]
    fn submission_json_is_ascending_and_deduped() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (_committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let mut signed = SignedRotationAck::new(sample_ack(), 7);
        // Sign out of order, with a repeat (ignored).
        for i in [4u16, 0, 3, 1, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        let json = signed.to_submission_json();

        let order: Vec<usize> = [0usize, 1, 3, 4]
            .iter()
            .map(|i| json.find(&format!(r#""voter_index":{i},"#)).expect("observer present"))
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "observers must be ascending: {json}");
        assert_eq!(json.matches(r#""voter_index""#).count(), 4, "no duplicate observers");

        assert!(json.contains(r#""chain_id":42"#));
        assert!(json.contains(r#""key_epoch":8"#));
        assert!(json.contains(r#""epoch":7"#));
        assert!(json.contains(&format!(r#""new_signer":"{}""#, "cd".repeat(20))));
        assert!(json.contains(r#""version":1"#), "the daemon accepts only the current version");
        assert!(json.contains(&format!(r#""contract":"{}""#, "22".repeat(20))));
        assert!(json.contains(&format!(r#""evm_txid":"{}""#, "ee".repeat(32))));
        assert!(json.contains(r#""log_index":3"#));
        for sig_hex in json.split(r#""signature":""#).skip(1) {
            assert_eq!(sig_hex.split('"').next().unwrap().len(), 128);
        }
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::ffi::{ed25519_keypair, ensure_init};

    fn committee(n: u16, t: u16) -> (CommitteeView, Vec<[u8; 64]>) {
        let (mut pks, mut sks) = (Vec::new(), Vec::new());
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        (
            CommitteeView {
                epoch: 7,
                height: 840,
                members: (0..n).map(|i| [i as u8; 32]).collect(),
                signer_keys: pks,
                member_ips: Vec::new(),
                member_x25519: Vec::new(),
                daemon_self_index: None,
                threshold: t as usize,
            },
            sks,
        )
    }

    fn ack(key_epoch: u64) -> RotationAck {
        RotationAck {
            chain_id: 56,
            contract: [0x22; 20],
            key_epoch,
            new_signer: [0xAB; 20],
            evm_txid: [key_epoch as u8; 32],
            log_index: 0,
        }
    }

    /// Members observe the rotation independently and each signs its own copy, so the
    /// threshold evidence has to be assembled by merging. Until it is, nothing can be
    /// submitted and the bond stays locked.
    #[test]
    fn signatures_from_separate_members_accumulate_to_threshold() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let genesis = [0x11u8; 32];

        // Each member signs its own copy, as it would having seen the event itself.
        let mut mine = SignedRotationAck::new(ack(2), c.epoch);
        mine.sign_as(0, &sks[0], &genesis).unwrap();
        assert_eq!(mine.valid_signature_count(&c, &genesis), 1);
        assert!(!mine.verify(&c, &genesis), "one signature is not threshold");

        for i in 1..4u16 {
            let mut theirs = SignedRotationAck::new(ack(2), c.epoch);
            theirs.sign_as(i, &sks[i as usize], &genesis).unwrap();
            assert!(mine.merge(&theirs), "same fact, so it merges");
        }

        assert_eq!(mine.valid_signature_count(&c, &genesis), 4);
        assert!(mine.verify(&c, &genesis), "four of six is threshold — submittable");
    }

    /// Two different rotations must never pool their signatures: the result would carry
    /// signatures over bytes nobody actually agreed on.
    #[test]
    fn signatures_for_a_different_rotation_are_refused() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let genesis = [0x11u8; 32];

        let mut mine = SignedRotationAck::new(ack(2), c.epoch);
        mine.sign_as(0, &sks[0], &genesis).unwrap();

        let mut other = SignedRotationAck::new(ack(3), c.epoch); // a different key epoch
        other.sign_as(1, &sks[1], &genesis).unwrap();

        assert!(!mine.merge(&other), "different fact must not merge");
        assert_eq!(mine.valid_signature_count(&c, &genesis), 1, "and nothing was absorbed");
    }

    /// Merging is idempotent: hearing the same member twice must not count it twice,
    /// or a single member could appear to be a whole quorum.
    #[test]
    fn hearing_the_same_member_twice_counts_once() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let genesis = [0x11u8; 32];

        let mut mine = SignedRotationAck::new(ack(2), c.epoch);
        let mut theirs = SignedRotationAck::new(ack(2), c.epoch);
        theirs.sign_as(1, &sks[1], &genesis).unwrap();

        for _ in 0..5 {
            assert!(mine.merge(&theirs));
        }
        assert_eq!(mine.valid_signature_count(&c, &genesis), 1);
        assert!(!mine.verify(&c, &genesis));
    }

    /// A signature that does not verify must not count toward threshold, even after a
    /// merge — merging is deliberately permissive, `verify` is the gate.
    #[test]
    fn a_forged_signature_never_counts() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let genesis = [0x11u8; 32];

        let mut mine = SignedRotationAck::new(ack(2), c.epoch);
        for i in 0..3u16 {
            mine.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        // A fourth "observer" whose signature is rubbish.
        mine.observers.push((3, [0x00; 64]));

        assert_eq!(mine.valid_signature_count(&c, &genesis), 3, "the forgery is ignored");
        assert!(!mine.verify(&c, &genesis), "3 real signatures is still short of 4");
    }
}

// ---- assembling threshold evidence over the mesh ----------------------------

/// Collects rotation-ack signatures until threshold, one entry per observed rotation.
///
/// Each member watches the EVM chain on its **own** RPC, sees the rotation for itself and
/// signs the same objective fact. Nobody is told what happened, so a member whose endpoint
/// lies to it simply signs different bytes and its signature does not match the others.
///
/// Entries are keyed by the canonical bytes of the fact, which is also what the mesh uses
/// as `payload_hash` — so two different rotations can never pool their signatures.
#[derive(Debug, Default)]
pub struct RotationAckCollector {
    pending: Vec<SignedRotationAck>,
}

/// Body of a [`SessionMsg::RotationAckSig`](crate::wire::SessionMsg): the sender's
/// committee index and its detached signature.
pub fn encode_ack_sig(committee_index: u16, sig: &[u8; 64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 64);
    v.extend_from_slice(&committee_index.to_le_bytes());
    v.extend_from_slice(sig);
    v
}

/// Reverse of [`encode_ack_sig`].
pub fn decode_ack_sig(body: &[u8]) -> Option<(u16, [u8; 64])> {
    if body.len() != 66 {
        return None;
    }
    let index = u16::from_le_bytes(body[0..2].try_into().ok()?);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&body[2..]);
    Some((index, sig))
}

impl RotationAckCollector {
    pub fn new() -> RotationAckCollector {
        RotationAckCollector { pending: Vec::new() }
    }

    /// Record this node's own observation and signature, returning the bytes to broadcast.
    ///
    /// Idempotent: observing the same rotation again re-broadcasts rather than duplicating,
    /// so a member that restarts mid-collection rejoins without corrupting the evidence.
    pub fn observe_and_sign(
        &mut self,
        ack: RotationAck,
        epoch: u64,
        self_index: u16,
        ed25519_sk64: &[u8; 64],
        genesis: &[u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        let entry = match self.pending.iter_mut().find(|p| p.ack == ack) {
            Some(e) => e,
            None => {
                self.pending.push(SignedRotationAck::new(ack, epoch));
                self.pending.last_mut().expect("just pushed")
            }
        };
        entry.sign_as(self_index, ed25519_sk64, genesis)?;
        let sig = entry
            .observers
            .iter()
            .find(|(i, _)| *i == self_index)
            .map(|(_, s)| *s)
            .ok_or("own signature missing after signing")?;
        Ok(encode_ack_sig(self_index, &sig))
    }

    /// Absorb a peer's signature for the rotation identified by `mesh_key`.
    ///
    /// The key must match a rotation this node has **also observed itself**. A signature
    /// for anything else is dropped: acknowledging a key change on someone else's word
    /// would let a peer's faulty or hostile RPC decide when a bond is released. Every
    /// acknowledgement this node contributes to rests on its own observation.
    ///
    /// The signature is not verified here — [`take_complete`](Self::take_complete) counts
    /// only signatures that check out, so absorbing a bad one can waste space but can
    /// never make an acknowledgement submittable.
    pub fn absorb(&mut self, mesh_key: &[u8; 32], body: &[u8], genesis: &[u8; 32]) -> bool {
        let Some((index, sig)) = decode_ack_sig(body) else {
            return false;
        };
        let Some(entry) = self
            .pending
            .iter_mut()
            .find(|p| &p.ack.mesh_key(genesis) == mesh_key)
        else {
            return false; // a rotation this node has not seen for itself
        };
        if entry.observers.iter().any(|(i, _)| *i == index) {
            return true; // already have this member's signature
        }
        entry.observers.push((index, sig));
        true
    }

    /// Any acknowledgement that now carries threshold-many *valid* signatures, removed
    /// from the collector so it is submitted once.
    pub fn take_complete(
        &mut self,
        committee: &CommitteeView,
        genesis: &[u8; 32],
    ) -> Vec<SignedRotationAck> {
        let mut out = Vec::new();
        self.pending.retain(|entry| {
            if entry.verify(committee, genesis) {
                out.push(entry.clone());
                false
            } else {
                true
            }
        });
        out
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// This node's own signature for each acknowledgement still collecting, as
    /// `(mesh_key, body)`: re-broadcast periodically so a member that started late, or
    /// missed the first broadcast, still receives it.
    pub fn own_signatures(&self, self_index: u16, genesis: &[u8; 32]) -> Vec<([u8; 32], Vec<u8>)> {
        self.pending
            .iter()
            .filter_map(|p| {
                let (_, sig) = p.observers.iter().find(|(i, _)| *i == self_index)?;
                Some((p.ack.mesh_key(genesis), encode_ack_sig(self_index, sig)))
            })
            .collect()
    }

    /// Forget an acknowledgement that L1 has already applied (its chain's observed key
    /// epoch reached it), so nothing keeps collecting for it.
    pub fn forget_observed(&mut self, observed: impl Fn(u64) -> Option<u64>) {
        self.pending
            .retain(|p| observed(p.ack.chain_id).is_none_or(|have| have < p.ack.key_epoch));
    }
}

/// Seconds between attempts to put a completed acknowledgement on chain.
pub const ACK_RETRY_SECS: u64 = 120;

/// Completed acknowledgements waiting to be applied on L1.
///
/// An acknowledgement is done only when L1's observed key epoch for its chain reaches it,
/// not when it is handed to the daemon: a wallet can be empty, a transaction can be
/// dropped, a member can restart. So each one is retried until the chain shows it, and
/// only the next epoch per chain is attempted, since consensus accepts no other.
#[derive(Debug, Default)]
pub struct AckSubmissions {
    waiting: Vec<(SignedRotationAck, u64)>, // (ack, unix secs of the last attempt; 0 = never)
}

impl AckSubmissions {
    pub fn new() -> AckSubmissions {
        AckSubmissions::default()
    }

    /// Add a completed acknowledgement (a repeat of one already waiting is ignored).
    pub fn add(&mut self, ack: SignedRotationAck) {
        if !self.waiting.iter().any(|(w, _)| w.ack == ack.ack) {
            self.waiting.push((ack, 0));
        }
    }

    /// Drop what L1 has already applied.
    pub fn forget_observed(&mut self, observed: impl Fn(u64) -> Option<u64>) {
        self.waiting.retain(|(w, _)| observed(w.ack.chain_id).is_none_or(|have| have < w.ack.key_epoch));
    }

    /// What to attempt now: per chain, the one acknowledgement consensus would accept next
    /// (exactly the next key epoch, or the lowest if the chain has none yet), if a retry
    /// interval has passed since its last attempt.
    pub fn due(&self, observed: impl Fn(u64) -> Option<u64>, now: u64) -> Vec<SignedRotationAck> {
        let mut chains: Vec<u64> = self.waiting.iter().map(|(w, _)| w.ack.chain_id).collect();
        chains.sort_unstable();
        chains.dedup();
        let mut out = Vec::new();
        for chain in chains {
            let next = match observed(chain) {
                Some(have) => self.waiting.iter().find(|(w, _)| w.ack.chain_id == chain && w.ack.key_epoch == have + 1),
                None => self
                    .waiting
                    .iter()
                    .filter(|(w, _)| w.ack.chain_id == chain)
                    .min_by_key(|(w, _)| w.ack.key_epoch),
            };
            if let Some((w, last)) = next {
                if now.saturating_sub(*last) >= ACK_RETRY_SECS {
                    out.push(w.clone());
                }
            }
        }
        out
    }

    /// Record an attempt, whatever its outcome; only L1 decides when it is done.
    pub fn attempted(&mut self, ack: &RotationAck, now: u64) {
        if let Some((_, last)) = self.waiting.iter_mut().find(|(w, _)| &w.ack == ack) {
            *last = now;
        }
    }

    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }
}

/// L1's observed key epoch per chain, from a `bridge_get_seats` JSON-RPC result.
#[cfg(feature = "evm-watcher")]
pub fn parse_observed_key_epochs(result: &serde_json::Value) -> Option<std::collections::BTreeMap<u64, u64>> {
    let mut out = std::collections::BTreeMap::new();
    for e in result.get("observed_key_epoch")?.as_array()? {
        out.insert(e.get("chain_id")?.as_u64()?, e.get("key_epoch")?.as_u64()?);
    }
    Some(out)
}

/// The `rotation_hex` from the daemon's `bridge.rotation_ack` reply.
#[cfg(feature = "evm-watcher")]
pub fn rotation_hex_from_reply(reply: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(reply).ok()?;
    v.get("rotation_hex")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod submission_tests {
    use super::*;

    fn signed(chain_id: u64, key_epoch: u64) -> SignedRotationAck {
        SignedRotationAck::new(
            RotationAck {
                chain_id,
                contract: [0x22; 20],
                key_epoch,
                new_signer: [0xAB; 20],
                evm_txid: [key_epoch as u8; 32],
                log_index: 0,
            },
            7,
        )
    }

    /// Only the epoch consensus would accept next is attempted, per chain, so an ack that
    /// completed out of order waits instead of being rejected over and over.
    #[test]
    fn only_the_next_epoch_per_chain_is_attempted() {
        let mut s = AckSubmissions::new();
        s.add(signed(56, 4));
        s.add(signed(56, 3));
        s.add(signed(1, 9));
        let observed = |c: u64| if c == 56 { Some(2) } else { None };
        let mut due: Vec<(u64, u64)> = s.due(observed, 1_000).iter().map(|a| (a.ack.chain_id, a.ack.key_epoch)).collect();
        due.sort();
        assert_eq!(due, vec![(1, 9), (56, 3)], "chain 1 has no epoch yet: its lowest; chain 56: 3, not 4");

        // Once L1 has 3, 4 is next.
        let after = |c: u64| if c == 56 { Some(3) } else { None };
        s.forget_observed(after);
        let due: Vec<u64> = s.due(after, 1_000).iter().filter(|a| a.ack.chain_id == 56).map(|a| a.ack.key_epoch).collect();
        assert_eq!(due, vec![4]);
    }

    /// Retried until L1 shows it, at most once per interval; done only when observed.
    #[test]
    fn an_ack_is_retried_until_l1_has_applied_it() {
        let mut s = AckSubmissions::new();
        s.add(signed(56, 3));
        s.add(signed(56, 3)); // a repeat is not a second entry
        assert_eq!(s.len(), 1);
        let observed = |_: u64| Some(2);
        assert_eq!(s.due(observed, 10_000).len(), 1);
        s.attempted(&signed(56, 3).ack, 10_000);
        assert!(s.due(observed, 10_000 + ACK_RETRY_SECS - 1).is_empty(), "not before the interval");
        assert_eq!(s.due(observed, 10_000 + ACK_RETRY_SECS).len(), 1, "then again");
        s.forget_observed(|_| Some(3));
        assert!(s.is_empty(), "applied on L1: done");
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn replies_are_parsed() {
        let seats = serde_json::json!({"observed_key_epoch": [{"chain_id": 56, "key_epoch": 3}, {"chain_id": 1, "key_epoch": 9}]});
        let m = parse_observed_key_epochs(&seats).unwrap();
        assert_eq!(m.get(&56), Some(&3));
        assert_eq!(m.get(&1), Some(&9));
        assert!(parse_observed_key_epochs(&serde_json::json!({})).is_none());
        assert_eq!(rotation_hex_from_reply(r#"{"rotation_hex":"0a0b","chain_id":56}"#).as_deref(), Some("0a0b"));
        assert_eq!(rotation_hex_from_reply("not json"), None);
    }
}

#[cfg(test)]
mod collector_tests {
    use super::*;
    use crate::ffi::{ed25519_keypair, ensure_init};

    fn committee(n: u16, t: u16) -> (CommitteeView, Vec<[u8; 64]>) {
        let (mut pks, mut sks) = (Vec::new(), Vec::new());
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        (
            CommitteeView {
                epoch: 7,
                height: 840,
                members: (0..n).map(|i| [i as u8; 32]).collect(),
                signer_keys: pks,
                member_ips: Vec::new(),
                member_x25519: Vec::new(),
                daemon_self_index: None,
                threshold: t as usize,
            },
            sks,
        )
    }
    fn ack(key_epoch: u64) -> RotationAck {
        RotationAck {
            chain_id: 56,
            contract: [0x22; 20],
            key_epoch,
            new_signer: [0xAB; 20],
            evm_txid: [key_epoch as u8; 32],
            log_index: 0,
        }
    }

    /// The whole point: independent observations converge into one submittable
    /// acknowledgement, which is what finally lets a departed member's bond release.
    #[test]
    fn independent_observations_assemble_into_submittable_evidence() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let g = [0x11u8; 32];

        // This node sees the rotation and signs it.
        let mut col = RotationAckCollector::new();
        let my_body = col.observe_and_sign(ack(2), c.epoch, 0, &sks[0], &g).unwrap();
        assert_eq!(my_body.len(), 66, "index + signature");
        assert!(col.take_complete(&c, &g).is_empty(), "one signature is not threshold");

        // Three peers, each having seen it on their own RPC, send theirs.
        let key = ack(2).mesh_key(&g);
        for i in 1..4u16 {
            let mut peer = RotationAckCollector::new();
            let body = peer.observe_and_sign(ack(2), c.epoch, i, &sks[i as usize], &g).unwrap();
            assert!(col.absorb(&key, &body, &g));
        }

        let done = col.take_complete(&c, &g);
        assert_eq!(done.len(), 1, "threshold reached — ready to submit");
        assert!(done[0].verify(&c, &g));
        assert!(col.take_complete(&c, &g).is_empty(), "taken once, not repeatedly");
    }

    /// A signature for a rotation this node has not seen itself must be refused —
    /// otherwise a peer's faulty or hostile RPC decides when a bond releases.
    #[test]
    fn a_signature_for_an_unobserved_rotation_is_refused() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let g = [0x11u8; 32];

        let mut col = RotationAckCollector::new();
        col.observe_and_sign(ack(2), c.epoch, 0, &sks[0], &g).unwrap();

        // A peer signs a DIFFERENT rotation (epoch 3) that we never observed.
        let mut peer = RotationAckCollector::new();
        let body = peer.observe_and_sign(ack(3), c.epoch, 1, &sks[1], &g).unwrap();

        assert!(!col.absorb(&ack(3).mesh_key(&g), &body, &g), "not our observation");
        assert_eq!(col.pending_len(), 1, "and nothing was created for it");
    }

    /// Two rotations in flight must keep their signatures apart.
    #[test]
    fn signatures_land_on_the_rotation_they_belong_to() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let g = [0x11u8; 32];

        // This node observed BOTH rotations.
        let mut col = RotationAckCollector::new();
        col.observe_and_sign(ack(2), c.epoch, 0, &sks[0], &g).unwrap();
        col.observe_and_sign(ack(3), c.epoch, 0, &sks[0], &g).unwrap();
        assert_eq!(col.pending_len(), 2);

        // Three peers sign only rotation 3.
        for i in 1..4u16 {
            let mut peer = RotationAckCollector::new();
            let body = peer.observe_and_sign(ack(3), c.epoch, i, &sks[i as usize], &g).unwrap();
            assert!(col.absorb(&ack(3).mesh_key(&g), &body, &g));
        }

        let done = col.take_complete(&c, &g);
        assert_eq!(done.len(), 1, "only rotation 3 reached threshold");
        assert_eq!(done[0].ack.key_epoch, 3, "and it is the right one");
        assert_eq!(col.pending_len(), 1, "rotation 2 still waiting, uncontaminated");
    }

    /// Restarting mid-collection must rejoin cleanly rather than double-sign.
    #[test]
    fn observing_the_same_rotation_twice_does_not_duplicate() {
        ensure_init().unwrap();
        let (c, sks) = committee(6, 4);
        let g = [0x11u8; 32];

        let mut col = RotationAckCollector::new();
        for _ in 0..3 {
            col.observe_and_sign(ack(2), c.epoch, 0, &sks[0], &g).unwrap();
        }
        assert_eq!(col.pending_len(), 1, "one entry, not three");
        assert!(col.take_complete(&c, &g).is_empty(), "still just one signature");
    }
}

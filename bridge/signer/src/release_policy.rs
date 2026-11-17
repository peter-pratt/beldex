//! The **release** [`ProposalPolicy`] — R1–R6 semantic admission
//! (design: `bridge/docs/AUTONOMY_SESSION_COORDINATION.md` §5;
//! ref rule: `bridge/docs/GATEWAY_RELEASE_REPLAY_GUARD.md` §4).
//!
//! A release is the leg where the signing message is **not** derivable by every node:
//! `gateway_create_transfer` builds an unsigned L1 tx with per-node decoy selection, so each
//! node's build yields a different `hash_to_sign`. Exactly one node — the session's
//! deterministic leader — builds the transaction; everyone else **admits or rejects it
//! semantically**, checking that it faithfully and uniquely discharges the burn they each
//! observed. A member never byte-reproduces the leader's tx and never signs one it did not
//! independently justify (C.5, with a predicate in place of byte-equality):
//!
//! * **R1 — burn provenance.** The proposal's `(chain_id, evm_txid, log_index)` names exactly
//!   the burn this member's own EVM watcher finalized (the duty it opened this session for).
//! * **R2 — destination.** The tx pays the burn's `beldex_recipient` — nothing else.
//! * **R3 — amount + fee.** Output amount `== burn_amount − fee`, where `fee` is exactly the
//!   redemption fee the burn's wBDX contract declares, and the burn exceeds it.
//! * **R4 — source + policy.** The tx spends the configured release gateway, and the amount is
//!   within the per-tx cap (the A.3 window caps + freeze are re-enforced at L1 submit).
//! * **R5 — hash binds the blob.** The proposed `hash_to_sign` is the `gateway_input_message`
//!   of *this* blob — checked via the member's **own** daemon (`TxInspector`), never taken
//!   from the leader.
//! * **R6 — release ref.** The proposal's burn tuple is what the L1 replay guard will record
//!   (`tx_extra_gateway_release_ref` carries the raw tuple; the ref hash is derived on-chain),
//!   so a signature can never discharge a *different* burn than the one verified. With the
//!   tuple carried raw, R6 is the same equality as R1 — kept separate in the docs because it
//!   guards a different property (replay binding, not provenance).
//!
//! An inspection failure (member's own RPC down) is an [`ProposalVerdict::Abstain`] — never a
//! NACK: the member cannot distinguish a bad proposal from its own outage, and an honest
//! leader must not be rotated out for it.

use crate::coordinator::{BuildError, ProposalPolicy, ProposalVerdict};
use crate::orchestrator::Duty;
use crate::session::NackReason;
use crate::watch::ReleaseEvent;
use std::collections::BTreeMap;

// ============================================================================
// Proposal codec
// ============================================================================

/// The leader's release proposal, broadcast in `Propose` and admitted by R1–R6.
///
/// `log_index` disambiguates multiple burns in one EVM tx: the watcher carries it, so a
/// proposal names the specific burn it discharges rather than being pinned at 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseProposal {
    pub version: u8,
    pub chain_id: u64,
    pub evm_txid: [u8; 32],
    pub log_index: u32,
    /// The withdrawal fee: the burn's contract's `redemptionFee` (R3).
    pub fee: u64,
    /// `gateway_input_message` of the blob — the 32 bytes `Pgw` signs. Never trusted as
    /// stated: re-derived from the blob by every verifier (R5).
    pub hash_to_sign: [u8; 32],
    /// The builder-disclosed **tx secret key**: verifiers open the withdrawal's stealth
    /// outputs with it (`gateway_decode_withdrawal`) to check destination + amount (R2/R3).
    /// Not a spend secret — it only reveals where this tx pays, which is exactly what
    /// verification requires.
    pub tx_key: [u8; 32],
    /// The unsigned withdrawal tx (`gateway_create_transfer` output), hex-free raw bytes.
    pub unsigned_tx_blob: Vec<u8>,
}

pub const RELEASE_PROPOSAL_VERSION: u8 = 1;

impl ReleaseProposal {
    /// Serialize (little-endian, length-prefixed blob).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 32 + 4 + 8 + 32 + 32 + 4 + self.unsigned_tx_blob.len());
        out.push(self.version);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.evm_txid);
        out.extend_from_slice(&self.log_index.to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.hash_to_sign);
        out.extend_from_slice(&self.tx_key);
        out.extend_from_slice(&(self.unsigned_tx_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.unsigned_tx_blob);
        out
    }

    /// Parse; `None` on truncation, bad version, or trailing garbage.
    pub fn decode(buf: &[u8]) -> Option<ReleaseProposal> {
        const FIXED: usize = 1 + 8 + 32 + 4 + 8 + 32 + 32 + 4;
        if buf.len() < FIXED || buf[0] != RELEASE_PROPOSAL_VERSION {
            return None;
        }
        let chain_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let mut evm_txid = [0u8; 32];
        evm_txid.copy_from_slice(&buf[9..41]);
        let log_index = u32::from_le_bytes(buf[41..45].try_into().unwrap());
        let fee = u64::from_le_bytes(buf[45..53].try_into().unwrap());
        let mut hash_to_sign = [0u8; 32];
        hash_to_sign.copy_from_slice(&buf[53..85]);
        let mut tx_key = [0u8; 32];
        tx_key.copy_from_slice(&buf[85..117]);
        let blob_len = u32::from_le_bytes(buf[117..121].try_into().unwrap()) as usize;
        let blob = buf.get(121..121 + blob_len)?;
        if buf.len() != 121 + blob_len {
            return None; // trailing garbage is not tolerated in a signed-off proposal
        }
        Some(ReleaseProposal {
            version: buf[0],
            chain_id,
            evm_txid,
            log_index,
            fee,
            hash_to_sign,
            tx_key,
            unsigned_tx_blob: blob.to_vec(),
        })
    }
}

// ============================================================================
// The inspection view (the member's own daemon's reading of the blob)
// ============================================================================

/// What a member's **own** daemon says the proposed blob actually does. Produced by the
/// injected inspector (`gateway_decode_withdrawal`-style RPC / a local parser), never by the
/// leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTxView {
    /// The gateway the tx spends from.
    pub source_gateway: String,
    /// The single wallet destination the tx pays.
    pub dest: Vec<u8>,
    /// The amount paid to `dest` (atomic units).
    pub amount: u128,
    /// The tx fee.
    pub fee: u64,
    /// `gateway_input_message` recomputed from **this** blob (R5's ground truth).
    pub hash_to_sign: [u8; 32],
    /// The release ref the blob itself carries, which is what consensus records as
    /// discharged. `None` unless the blob carries exactly one well-formed version-0 ref.
    pub release_ref: Option<ReleaseRef>,
    /// The recipient can actually use the payout: every output unlocked, and the tx's
    /// public key is the disclosed key's, so the wallet derives the same outputs the
    /// inspection opened. Without this a correct destination and amount can still pay
    /// money locked for decades, or money the recipient's wallet never finds.
    pub payout_spendable: bool,
}

/// The burn a withdrawal discharges, as carried in its `tx_extra_gateway_release_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRef {
    pub chain_id: u64,
    pub evm_txid: [u8; 32],
    pub log_index: u32,
}

/// The built release the leader hands to the codec (the `gateway_create_transfer` result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltRelease {
    pub unsigned_tx_blob: Vec<u8>,
    pub hash_to_sign: [u8; 32],
    pub fee: u64,
    /// The builder-disclosed tx secret key (see [`ReleaseProposal::tx_key`]).
    pub tx_key: [u8; 32],
}

// ============================================================================
// ReleasePolicy
// ============================================================================

/// The release-leg [`ProposalPolicy`]: leader-side build via the injected tx builder
/// (`gateway_create_transfer` + the replay-guard ref attach), member-side R1–R6 admission via
/// the injected inspector. Both seams are closures so the policy is std-only testable.
pub struct ReleasePolicy<Build, Inspect>
where
    Build: FnMut(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
    Inspect: FnMut(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
{
    /// Leader only: build the withdrawal for a burn (side-effectful — talks to the daemon).
    pub build_tx: Build,
    /// Member: this node's own reading of a proposed withdrawal — `(proposal,
    /// expected_recipient)` → the verified view (R2/R3/R4/R5 ground truth). The live
    /// implementation calls the member's own daemon's `gateway_decode_withdrawal` with the
    /// proposal's blob + disclosed `tx_key` + the expected recipient address.
    pub inspect: Inspect,
    /// The committee's release gateway (R4).
    pub release_gateway: String,
    /// Chain id → the `redemptionFee` that chain's wBDX contract declares (R3). Every
    /// release for a burn on that chain pays exactly this fee, so the payout the contract
    /// promised when it accepted the burn is the payout the committee signs.
    pub fees: BTreeMap<u64, u64>,
    /// Per-tx amount cap (R4); the window caps are enforced at L1 submit.
    pub per_tx_cap: u128,
}

impl<Build, Inspect> ReleasePolicy<Build, Inspect>
where
    Build: FnMut(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
    Inspect: FnMut(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
{
    /// R1–R6 against this member's own burn observation + its own inspection of the blob.
    fn admit(&mut self, ev: &ReleaseEvent, p: &ReleaseProposal) -> ProposalVerdict {
        use ProposalVerdict::{Abstain, Accept, Reject};
        let reject = Reject(NackReason::PayloadMismatch);

        // R1: the proposal names exactly the burn this session is for (provenance).
        if p.chain_id != ev.chain.0 || p.evm_txid != ev.evm_txid || p.log_index != ev.log_index {
            return reject;
        }
        // R3 precondition: exactly the contract's fee, and a burn that exceeds it (a fee at
        // or above the burn would leave nothing, or underflow, to pay).
        if self.fees.get(&ev.chain.0) != Some(&p.fee) || u128::from(p.fee) >= ev.amount {
            return reject;
        }

        // R5 ground truth: this member's own daemon reads the proposed withdrawal (blob +
        // disclosed tx_key) against the burn's recipient. Outage → Abstain.
        let view = match (self.inspect)(p, &ev.beldex_recipient) {
            Ok(v) => v,
            Err(_) => return Abstain,
        };

        // R5: the proposed hash is the gateway_input_message of *this* blob.
        if view.hash_to_sign != p.hash_to_sign {
            return reject;
        }
        // R6: the blob discharges this burn. The leader's metadata above is only a claim;
        // the replay guard records the ref inside the signed tx. A blob paying this burn's
        // recipient while carrying another burn's ref would leave this burn open to a second
        // payout and close the other one unpaid.
        let expected = ReleaseRef { chain_id: ev.chain.0, evm_txid: ev.evm_txid, log_index: ev.log_index };
        if view.release_ref != Some(expected) {
            return reject;
        }
        // R2 (usable): paying the recipient means paying something it can spend.
        if !view.payout_spendable {
            return reject;
        }
        // R2: pays the burn's recipient.
        if view.dest != ev.beldex_recipient {
            return reject;
        }
        // R3: amount + fee faithful.
        if view.fee != p.fee || view.amount != ev.amount - u128::from(p.fee) {
            return reject;
        }
        // R4: spends the committee's release gateway, within the per-tx cap.
        if view.source_gateway != self.release_gateway || ev.amount > self.per_tx_cap {
            return reject;
        }
        Accept
    }
}

/// Could these bytes be a Beldex address at all?
///
/// Deliberately a shape test, not a validation: it must be cheap enough for the
/// `actionable` path and must never reject something the daemon would have accepted. Beldex
/// addresses are base58, so any byte outside that alphabet — or a non-UTF-8 recipient — is
/// proof the daemon cannot use it. `0`, `O`, `I` and `l` are excluded from base58 precisely
/// because they are easy to confuse, which is also how a mistyped address usually fails.
fn is_possible_beldex_address(recipient: &[u8]) -> bool {
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    !recipient.is_empty()
        && std::str::from_utf8(recipient).is_ok()
        && recipient.iter().all(|c| BASE58.contains(c))
}

/// Does `recipient` carry a valid address checksum?
///
/// A Beldex address is CryptoNote base58 (8-byte blocks as 11 characters, the last block
/// shorter) over `prefix ‖ keys ‖ checksum`, the checksum being the first 4 bytes of
/// Keccak-256 over everything before it. A mistyped address that stays inside the alphabet
/// fails here, on every node alike — otherwise only the leader learns it from the daemon at
/// `build`, and every other member keeps reopening a session for it. The checksum alone is
/// checked, not the network prefix or the length, so nothing the daemon accepts is refused.
#[cfg(any(feature = "evm-watcher", feature = "tss-integration"))]
fn has_valid_address_checksum(recipient: &[u8]) -> bool {
    use sha3::{Digest, Keccak256};
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Characters per encoded block, by decoded size 0..=8.
    const ENCODED_SIZE: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    let mut data = Vec::with_capacity(recipient.len());
    for block in recipient.chunks(11) {
        let Some(size) = ENCODED_SIZE.iter().position(|&n| n == block.len()) else {
            return false;
        };
        let mut num: u128 = 0;
        for c in block {
            let Some(digit) = BASE58.iter().position(|b| b == c) else {
                return false;
            };
            num = num * 58 + digit as u128;
        }
        if num >> (8 * size) != 0 {
            return false; // overflows its block
        }
        data.extend_from_slice(&(num as u64).to_be_bytes()[8 - size..]);
    }
    if data.len() <= 4 {
        return false;
    }
    let (body, checksum) = data.split_at(data.len() - 4);
    Keccak256::digest(body)[..4] == *checksum
}
#[cfg(not(any(feature = "evm-watcher", feature = "tss-integration")))]
fn has_valid_address_checksum(_recipient: &[u8]) -> bool {
    true // no Keccak in this build: left to the daemon at `build`
}

impl<Build, Inspect> ProposalPolicy for ReleasePolicy<Build, Inspect>
where
    Build: FnMut(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
    Inspect: FnMut(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
{
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Release(ev) => {
                // Over-cap burns are permanently unactionable under this policy (a cap raise
                // is a new policy → new process lifecycle); everything else is workable.
                if ev.amount > self.per_tx_cap {
                    return Err(BuildError::Unactionable("burn exceeds the per-tx release cap".into()));
                }
                // The contract refuses such burns now, but one accepted before it did, or on
                // a chain this node has no fee for, can never be paid under R3.
                match self.fees.get(&ev.chain.0) {
                    None => {
                        return Err(BuildError::Unactionable("no redemption fee for the burn's chain".into()))
                    }
                    Some(&fee) if ev.amount <= u128::from(fee) => {
                        return Err(BuildError::Unactionable("burn does not exceed the redemption fee".into()))
                    }
                    Some(_) => {}
                }
                // A recipient the daemon can never decode is permanently unactionable, and it
                // has to be judged HERE rather than in `build`. Only the leader builds, so a
                // leader-side give-up leaves every other member holding a session open for a
                // proposal that will never arrive — they time out, reopen, and repeat for the
                // life of the process. This check runs on every node, so they all retire the
                // duty together.
                //
                // Shape only, because this must stay cheap and side-effect-free: a character
                // outside the base58 alphabet cannot appear in any Beldex address, on any
                // network, so rejecting it can never strand a payable release. A recipient
                // that is base58-clean but fails the daemon's checksum still reaches `build`.
                if !is_possible_beldex_address(&ev.beldex_recipient) {
                    return Err(BuildError::Unactionable(
                        "burn recipient is not a possible Beldex address".into(),
                    ));
                }
                // ...unless its checksum is checked here too, which is just as cheap.
                if !has_valid_address_checksum(&ev.beldex_recipient) {
                    return Err(BuildError::Unactionable(
                        "burn recipient fails the Beldex address checksum".into(),
                    ));
                }
                Ok(())
            }
            _ => Err(BuildError::Unactionable(
                "the release policy handles only releases (use DualPolicy)".into(),
            )),
        }
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        let Duty::Release(ev) = duty else {
            return Err(BuildError::Unactionable("not a release duty".into()));
        };
        let built = (self.build_tx)(ev)?;
        Ok(ReleaseProposal {
            version: RELEASE_PROPOSAL_VERSION,
            chain_id: ev.chain.0,
            evm_txid: ev.evm_txid,
            log_index: ev.log_index,
            fee: built.fee,
            hash_to_sign: built.hash_to_sign,
            tx_key: built.tx_key,
            unsigned_tx_blob: built.unsigned_tx_blob,
        }
        .encode())
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        let Duty::Release(ev) = duty else {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        };
        let Some(p) = ReleaseProposal::decode(proposal) else {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        };
        self.admit(ev, &p)
    }

    fn signing_message(&self, _duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        // Only ever called on an *accepted* proposal, so decode cannot fail; return empty on
        // the impossible path rather than panicking a signer.
        ReleaseProposal::decode(proposal).map(|p| p.hash_to_sign.to_vec()).unwrap_or_default()
    }
}

// ============================================================================
// DualPolicy — the production composition (mints + releases in one Coordinator)
// ============================================================================

/// Dispatches by duty kind: mints to `M`, releases to `R`, takeover cancels to `C`, the wBDX
/// key hand-off to `T` and the gateway's to `H`. This is what `serve --live` runs.
pub struct DualPolicy<M: ProposalPolicy, R: ProposalPolicy, C: ProposalPolicy, T: ProposalPolicy, H: ProposalPolicy> {
    pub mint: M,
    pub release: R,
    pub cancel: C,
    pub rotate: T,
    pub handover: H,
}

impl<M: ProposalPolicy, R: ProposalPolicy, C: ProposalPolicy, T: ProposalPolicy, H: ProposalPolicy> ProposalPolicy
    for DualPolicy<M, R, C, T, H>
{
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Mint(_) => self.mint.actionable(duty),
            Duty::Release(_) => self.release.actionable(duty),
            Duty::Takeover(_) => self.cancel.actionable(duty),
            Duty::Rotate(_) => self.rotate.actionable(duty),
            Duty::Handover(_) => self.handover.actionable(duty),
        }
    }
    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        match duty {
            Duty::Mint(_) => self.mint.build(duty),
            Duty::Release(_) => self.release.build(duty),
            Duty::Takeover(_) => self.cancel.build(duty),
            Duty::Rotate(_) => self.rotate.build(duty),
            Duty::Handover(_) => self.handover.build(duty),
        }
    }
    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        match duty {
            Duty::Mint(_) => self.mint.verify(duty, proposal),
            Duty::Release(_) => self.release.verify(duty, proposal),
            Duty::Takeover(_) => self.cancel.verify(duty, proposal),
            Duty::Rotate(_) => self.rotate.verify(duty, proposal),
            Duty::Handover(_) => self.handover.verify(duty, proposal),
        }
    }
    fn signing_message(&self, duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        match duty {
            Duty::Mint(_) => self.mint.signing_message(duty, proposal),
            Duty::Release(_) => self.release.signing_message(duty, proposal),
            Duty::Takeover(_) => self.cancel.signing_message(duty, proposal),
            Duty::Rotate(_) => self.rotate.signing_message(duty, proposal),
            Duty::Handover(_) => self.handover.signing_message(duty, proposal),
        }
    }
}

// ============================================================================
// HandoverPolicy — the outgoing committee's Pgw signature on the gateway hand-over
// ============================================================================

/// What a member's own daemon says an unsigned descriptor update does
/// (`gateway_decode_descriptor_update`): the daemon refuses anything but one update of one
/// gateway, with no gateway input riding along.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorUpdateView {
    pub gateway_id: [u8; 32],
    pub owner_key_type: String,
    pub owner_key: Vec<u8>,
    pub bridge_reserve: bool,
    /// Whether the update names a standby. A hand-over never does: the standby is named by the
    /// committee that will own the gateway, through consensus' own naming rule.
    pub has_standby: bool,
    pub hash_to_sign: [u8; 32],
}

/// The gateway hand-over to a [`crate::orchestrator::HandoverRequest`]'s new owner, raised
/// only for a `Pgw` whose certificate every member checked. The transaction is built by the
/// wallet that pays its fee — the hand-over submitter's, so the leader `fetch`es it from the
/// submitter for the request's new owner. The submitter is not trusted: the proposal is
/// `hash_to_sign ‖ tx_blob`, and each member `decode`s the blob on its own daemon and signs
/// only an update of this gateway to exactly that owner, keeping the reserve flag, whose
/// recomputed hash is the one proposed.
pub struct HandoverPolicy<Fetch, Decode>
where
    Fetch: FnMut(&[u8; 32]) -> Result<Vec<u8>, String>,
    Decode: FnMut(&[u8]) -> Result<DescriptorUpdateView, String>,
{
    pub fetch: Fetch,
    pub decode: Decode,
    /// The bridge reserve gateway this committee owns.
    pub gateway_id: [u8; 32],
}

impl<Fetch, Decode> HandoverPolicy<Fetch, Decode>
where
    Fetch: FnMut(&[u8; 32]) -> Result<Vec<u8>, String>,
    Decode: FnMut(&[u8]) -> Result<DescriptorUpdateView, String>,
{
    fn request<'d>(&self, duty: &'d Duty) -> Result<&'d crate::orchestrator::HandoverRequest, BuildError> {
        match duty {
            Duty::Handover(h) if h.gateway_id == self.gateway_id => Ok(h),
            Duty::Handover(_) => Err(BuildError::Unactionable("not this committee's gateway".into())),
            _ => Err(BuildError::Unactionable("not a gateway hand-over".into())),
        }
    }

    fn hands_over(&self, view: &DescriptorUpdateView, h: &crate::orchestrator::HandoverRequest) -> bool {
        view.gateway_id == self.gateway_id
            && view.owner_key_type == "eddsa"
            && view.owner_key[..] == h.new_owner[..]
            && view.bridge_reserve
            && !view.has_standby
    }
}

impl<Fetch, Decode> ProposalPolicy for HandoverPolicy<Fetch, Decode>
where
    Fetch: FnMut(&[u8; 32]) -> Result<Vec<u8>, String>,
    Decode: FnMut(&[u8]) -> Result<DescriptorUpdateView, String>,
{
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        self.request(duty).map(|_| ())
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        let h = self.request(duty)?.clone();
        let blob = (self.fetch)(&h.new_owner).map_err(|e| BuildError::Transient(format!("hand-over builder: {e}")))?;
        let view = (self.decode)(&blob).map_err(|e| BuildError::Transient(format!("decode the built hand-over: {e}")))?;
        if !self.hands_over(&view, &h) {
            return Err(BuildError::Transient("the builder returned something other than this hand-over".into()));
        }
        Ok([&view.hash_to_sign[..], &blob[..]].concat())
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        let Ok(h) = self.request(duty).cloned() else { return ProposalVerdict::Reject(NackReason::PayloadMismatch) };
        if proposal.len() <= 32 {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        }
        let Ok(view) = (self.decode)(&proposal[32..]) else { return ProposalVerdict::Abstain };
        if self.hands_over(&view, &h) && view.hash_to_sign[..] == proposal[..32] {
            ProposalVerdict::Accept
        } else {
            ProposalVerdict::Reject(NackReason::PayloadMismatch)
        }
    }

    fn signing_message(&self, _duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        proposal[..32].to_vec()
    }
}

// ============================================================================
// RotatePolicy — the outgoing committee's rotateSigner
// ============================================================================

/// What the wBDX contract on one chain says about key hand-offs, read by each member from its
/// own RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationState {
    pub key_epoch: u64,
    pub rotation_nonce: u64,
    /// 0 when no rotation is pending.
    pub pending_activate_at: u64,
    /// The chain's latest block time: the clock the authorization's deadline is checked on.
    pub now: u64,
}

/// `keccak256("BELDEX_BRIDGE_ROTATE_V1")`, `WrappedBDX.ROTATE_TAG`.
pub const ROTATE_TAG: [u8; 32] = [
    0x1f, 0x16, 0x84, 0x94, 0xb9, 0xc1, 0x65, 0xfd, 0xb7, 0x61, 0x7d, 0x54, 0xf9, 0x47, 0x4d, 0x57,
    0xca, 0x55, 0xd8, 0xbb, 0x4d, 0x3f, 0x59, 0x60, 0xfa, 0x2e, 0x09, 0xa8, 0x1a, 0xba, 0x1f, 0xbd,
];

/// `abi.encode(ROTATE_TAG, chainid, contract, newKeyEpoch, newSigner, nonce, deadline)`, the
/// preimage `rotateSigner` recovers the outgoing key from.
pub fn rotate_preimage(chain_id: u64, contract: [u8; 20], new_key_epoch: u64, new_signer: [u8; 20], nonce: u64, deadline: u64) -> Vec<u8> {
    let word = |tail: &[u8]| {
        let mut w = [0u8; 32];
        w[32 - tail.len()..].copy_from_slice(tail);
        w
    };
    [
        ROTATE_TAG,
        word(&chain_id.to_be_bytes()),
        word(&contract),
        word(&new_key_epoch.to_be_bytes()),
        word(&new_signer),
        word(&nonce.to_be_bytes()),
        word(&deadline.to_be_bytes()),
    ]
    .concat()
}

/// `keccak256("BELDEX_BRIDGE_ACTIVATE_V1")`, `WrappedBDX.ACTIVATE_TAG`.
pub const ACTIVATE_TAG: [u8; 32] = [
    0xdd, 0xe1, 0xd7, 0x51, 0x43, 0xfa, 0xf5, 0x92, 0x91, 0xdd, 0x47, 0x2b, 0xa9, 0x22, 0x6a, 0x06,
    0x04, 0xd9, 0xeb, 0x61, 0x3b, 0x71, 0x94, 0x5f, 0x05, 0x9f, 0xbc, 0x93, 0x65, 0xd5, 0x68, 0x04,
];

/// `abi.encode(ACTIVATE_TAG, chainid, contract, pendingKeyEpoch, pendingSigner)`, the preimage
/// `activateRotation` recovers the incoming key from.
pub fn activate_preimage(chain_id: u64, contract: [u8; 20], pending_key_epoch: u64, pending_signer: [u8; 20]) -> Vec<u8> {
    let word = |tail: &[u8]| {
        let mut w = [0u8; 32];
        w[32 - tail.len()..].copy_from_slice(tail);
        w
    };
    [ACTIVATE_TAG, word(&chain_id.to_be_bytes()), word(&contract), word(&pending_key_epoch.to_be_bytes()), word(&pending_signer)]
        .concat()
}

/// The outgoing committee's `rotateSigner` to a [`crate::orchestrator::RotationRequest`]: a
/// request is raised only for a key whose certificate and activation each member checked, so
/// what is left to agree is the contract's side. The leader proposes the exact preimage from
/// its own reading; each member re-reads the contract and accepts only the next key epoch, the
/// next nonce, this request's signer, and a deadline `valid_secs` after the chain's clock —
/// within half to twice that, since members read the clock moments apart.
pub struct RotatePolicy<Read: FnMut(u64) -> Result<RotationState, String>> {
    pub read: Read,
    /// `chain_id` → wBDX contract, as for mints.
    pub contracts: BTreeMap<u64, [u8; 20]>,
    pub valid_secs: u64,
}

impl<Read: FnMut(u64) -> Result<RotationState, String>> RotatePolicy<Read> {
    fn request<'d>(&self, duty: &'d Duty) -> Result<&'d crate::orchestrator::RotationRequest, BuildError> {
        match duty {
            Duty::Rotate(r) if self.contracts.get(&r.chain_id) == Some(&r.contract) => Ok(r),
            Duty::Rotate(r) => Err(BuildError::Unactionable(format!("no such wBDX on chain {}", r.chain_id))),
            _ => Err(BuildError::Unactionable("not a rotation".into())),
        }
    }
}

impl<Read: FnMut(u64) -> Result<RotationState, String>> ProposalPolicy for RotatePolicy<Read> {
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        self.request(duty).map(|_| ())
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        let r = self.request(duty)?.clone();
        let st = (self.read)(r.chain_id).map_err(BuildError::Transient)?;
        if st.key_epoch + 1 != r.new_key_epoch {
            return Err(BuildError::Unactionable(format!(
                "for key epoch {}, and the contract is at {}",
                r.new_key_epoch, st.key_epoch
            )));
        }
        if st.pending_activate_at != 0 {
            return Err(BuildError::Unactionable("a rotation is already pending".into()));
        }
        Ok(rotate_preimage(r.chain_id, r.contract, r.new_key_epoch, r.new_signer, st.rotation_nonce + 1, st.now + self.valid_secs))
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        let Ok(r) = self.request(duty).cloned() else { return ProposalVerdict::Reject(NackReason::PayloadMismatch) };
        let Ok(st) = (self.read)(r.chain_id) else { return ProposalVerdict::Abstain };
        if proposal.len() != 7 * 32 || st.pending_activate_at != 0 {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        }
        let deadline_word = &proposal[6 * 32..];
        if deadline_word[..24].iter().any(|b| *b != 0) {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        }
        let deadline = u64::from_be_bytes(deadline_word[24..].try_into().expect("8 bytes"));
        let fresh = deadline >= st.now + self.valid_secs / 2 && deadline <= st.now + 2 * self.valid_secs;
        let expected = rotate_preimage(r.chain_id, r.contract, r.new_key_epoch, r.new_signer, st.rotation_nonce + 1, deadline);
        if fresh && st.key_epoch + 1 == r.new_key_epoch && expected == proposal {
            ProposalVerdict::Accept
        } else {
            ProposalVerdict::Reject(NackReason::PayloadMismatch)
        }
    }

    fn signing_message(&self, _duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        proposal.to_vec()
    }
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;
    use crate::coordinator::test_support::{committee, mock_sign, mock_verify, Bus};
    use crate::coordinator::{sha256, Coordinator, MintPolicy};
    use crate::orchestrator::{DutyKey, ExecOutcome, Orchestrator};
    use crate::transport::Leg;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    // ---- a toy withdrawal format the mock daemon builds + inspects ----------
    //
    // blob = [src_len u8][src][dest_len u8][dest][amount u128 le][fee u64 le]
    //        [ref_count u8]([chain_id u64 le][evm_txid 32][log_index u32 le])*
    // hash_to_sign = sha256(blob)  (stands in for gateway_input_message)

    /// A blob carrying the ref of [`burn`], which every toy withdrawal is for.
    fn toy_blob(src: &str, dest: &[u8], amount: u128, fee: u64) -> Vec<u8> {
        let r = ReleaseRef { chain_id: 1, evm_txid: [0x77; 32], log_index: 0 };
        toy_blob_with_refs(src, dest, amount, fee, &[r])
    }

    fn toy_blob_with_refs(src: &str, dest: &[u8], amount: u128, fee: u64, refs: &[ReleaseRef]) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(src.len() as u8);
        b.extend_from_slice(src.as_bytes());
        b.push(dest.len() as u8);
        b.extend_from_slice(dest);
        b.extend_from_slice(&amount.to_le_bytes());
        b.extend_from_slice(&fee.to_le_bytes());
        b.push(refs.len() as u8);
        for r in refs {
            b.extend_from_slice(&r.chain_id.to_le_bytes());
            b.extend_from_slice(&r.evm_txid);
            b.extend_from_slice(&r.log_index.to_le_bytes());
        }
        b
    }

    fn toy_inspect(p: &ReleaseProposal, _expected_dest: &[u8]) -> Result<ReleaseTxView, String> {
        toy_inspect_blob(&p.unsigned_tx_blob)
    }

    fn toy_inspect_blob(blob: &[u8]) -> Result<ReleaseTxView, String> {
        let src_len = *blob.first().ok_or("truncated")? as usize;
        let src = blob.get(1..1 + src_len).ok_or("truncated")?;
        let mut at = 1 + src_len;
        let dest_len = *blob.get(at).ok_or("truncated")? as usize;
        at += 1;
        let dest = blob.get(at..at + dest_len).ok_or("truncated")?;
        at += dest_len;
        let amount = u128::from_le_bytes(blob.get(at..at + 16).ok_or("truncated")?.try_into().unwrap());
        at += 16;
        let fee = u64::from_le_bytes(blob.get(at..at + 8).ok_or("truncated")?.try_into().unwrap());
        at += 8;
        let ref_count = *blob.get(at).ok_or("truncated")? as usize;
        at += 1;
        let mut refs = Vec::new();
        for _ in 0..ref_count {
            let r = blob.get(at..at + 44).ok_or("truncated")?;
            refs.push(ReleaseRef {
                chain_id: u64::from_le_bytes(r[..8].try_into().unwrap()),
                evm_txid: r[8..40].try_into().unwrap(),
                log_index: u32::from_le_bytes(r[40..].try_into().unwrap()),
            });
            at += 44;
        }
        Ok(ReleaseTxView {
            source_gateway: String::from_utf8_lossy(src).into_owned(),
            dest: dest.to_vec(),
            amount,
            fee,
            hash_to_sign: sha256(blob),
            // As the live inspector reports it: exactly one ref, or none at all.
            release_ref: if refs.len() == 1 { Some(refs[0]) } else { None },
            payout_spendable: true,
        })
    }

    const GW: &str = "gwRelease";
    const FEE: u64 = 25;

    fn toy_build(ev: &ReleaseEvent) -> Result<BuiltRelease, BuildError> {
        let r = ReleaseRef { chain_id: ev.chain.0, evm_txid: ev.evm_txid, log_index: ev.log_index };
        let blob = toy_blob_with_refs(GW, &ev.beldex_recipient, ev.amount - u128::from(FEE), FEE, &[r]);
        let hash = sha256(&blob);
        Ok(BuiltRelease { unsigned_tx_blob: blob, hash_to_sign: hash, fee: FEE, tx_key: [0xAB; 32] })
    }

    type TestReleasePolicy = ReleasePolicy<
        fn(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
        fn(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
    >;

    fn policy() -> TestReleasePolicy {
        ReleasePolicy {
            build_tx: toy_build as fn(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
            inspect: toy_inspect as fn(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
            release_gateway: GW.to_string(),
            fees: toy_fees(),
            per_tx_cap: 1_000_000,
        }
    }

    /// The toy chain 1 declares the toy builder's fee.
    fn toy_fees() -> BTreeMap<u64, u64> {
        BTreeMap::from([(1, FEE)])
    }

    fn burn(amount: u128) -> ReleaseEvent {
        ReleaseEvent {
            evm_txid: [0x77; 32], log_index: 0,
            chain: ChainId(1),
            amount,
            // A real address: `actionable` checks the checksum.
            beldex_recipient: b"59sr6Ez6CQKJ7Uq3akAAS7K9jebF1VHnjZtTLXuzjCX5fsiWMsaap2h6uUu4tZUJo4jSxQ8vtGKUvKwpkZB2WKJSQfeRnhJ".to_vec(),
        }
    }

    fn proposal_for(ev: &ReleaseEvent) -> ReleaseProposal {
        let mut p = policy();
        let bytes = p.build(&Duty::Release(ev.clone())).expect("build");
        ReleaseProposal::decode(&bytes).expect("decode")
    }

    // ---- codec --------------------------------------------------------------

    #[test]
    fn proposal_codec_round_trips_and_rejects_malformed() {
        let p = proposal_for(&burn(1000));
        let bytes = p.encode();
        assert_eq!(ReleaseProposal::decode(&bytes), Some(p.clone()));

        assert_eq!(ReleaseProposal::decode(&bytes[..40]), None, "truncated header");
        let mut bad = bytes.clone();
        bad[0] = 9;
        assert_eq!(ReleaseProposal::decode(&bad), None, "unknown version");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(ReleaseProposal::decode(&trailing), None, "trailing garbage");
    }

    // ---- R1–R6 admission ----------------------------------------------------

    #[test]
    fn a_faithful_proposal_is_accepted_and_signs_the_proposed_hash() {
        let ev = burn(1000);
        let p = proposal_for(&ev);
        let duty = Duty::Release(ev);
        let mut pol = policy();
        assert_eq!(pol.verify(&duty, &p.encode()), ProposalVerdict::Accept);
        assert_eq!(
            pol.signing_message(&duty, &p.encode()),
            p.hash_to_sign.to_vec(),
            "Pgw signs exactly the proposed (and re-derived) hash"
        );
    }

    #[test]
    fn burns_the_contract_fee_would_consume_are_unactionable() {
        let pol = policy();
        let unactionable = |ev: ReleaseEvent| {
            matches!(pol.actionable(&Duty::Release(ev)), Err(BuildError::Unactionable(_)))
        };
        assert!(unactionable(burn(u128::from(FEE))), "pays nothing");
        assert!(unactionable(burn(u128::from(FEE) - 1)), "less than nothing");
        assert!(!unactionable(burn(u128::from(FEE) + 1)));
        let mut other_chain = burn(1000);
        other_chain.chain = ChainId(2);
        assert!(unactionable(other_chain), "no fee known for the chain");
    }

    #[test]
    fn every_violation_is_rejected_with_payload_mismatch() {
        let ev = burn(1000);
        let duty = Duty::Release(ev.clone());
        let reject = ProposalVerdict::Reject(NackReason::PayloadMismatch);

        // R1: names a different burn (txid / chain / log_index).
        for tamper in [
            {
                let mut p = proposal_for(&ev);
                p.evm_txid = [0x78; 32];
                p
            },
            {
                let mut p = proposal_for(&ev);
                p.chain_id = 2;
                p
            },
            {
                let mut p = proposal_for(&ev);
                p.log_index = 1;
                p
            },
        ] {
            assert_eq!(policy().verify(&duty, &tamper.encode()), reject, "R1/R6: {tamper:?}");
        }

        // R2: pays someone else (blob rebuilt so R5 still holds — isolates R2).
        {
            let blob = toy_blob(GW, b"attacker", ev.amount - u128::from(FEE), FEE);
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R2");
        }
        // R3: wrong amount.
        {
            let blob = toy_blob(GW, &ev.beldex_recipient, ev.amount, FEE); // skims nothing but pays too much
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R3 amount");
        }
        // R3: any fee but the contract's, above or below it. Blob rebuilt so the amount
        // still adds up — the fee alone is wrong.
        for fee in [FEE + 1, FEE - 1, 0] {
            let blob = toy_blob(GW, &ev.beldex_recipient, ev.amount - u128::from(fee), fee);
            let p = ReleaseProposal {
                fee,
                hash_to_sign: sha256(&blob),
                unsigned_tx_blob: blob,
                ..proposal_for(&ev)
            };
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R3 fee {fee}");
        }
        // R4: spends the wrong gateway.
        {
            let blob = toy_blob("gwEvil", &ev.beldex_recipient, ev.amount - u128::from(FEE), FEE);
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R4 source");
        }
        // R5: hash does not bind the blob (tampered blob, stated hash unchanged).
        {
            let mut p = proposal_for(&ev);
            p.unsigned_tx_blob = toy_blob(GW, b"attacker", ev.amount - u128::from(FEE), FEE);
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R5");
        }
        // R6: metadata names this burn, but the blob carries another ref, none, or two.
        // Only the blob's ref is recorded on chain, so each would leave this burn open.
        let this = ReleaseRef { chain_id: 1, evm_txid: [0x77; 32], log_index: 0 };
        let other_burn = ReleaseRef { evm_txid: [0x99; 32], ..this };
        let other_log = ReleaseRef { log_index: 7, ..this };
        let other_chain = ReleaseRef { chain_id: 2, ..this };
        for refs in [
            vec![other_burn],
            vec![other_log],
            vec![other_chain],
            vec![],
            vec![this, this],
            vec![this, other_burn],
        ] {
            let blob =
                toy_blob_with_refs(GW, &ev.beldex_recipient, ev.amount - u128::from(FEE), FEE, &refs);
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R6 refs {refs:?}");
        }
        // R2 (usable): the daemon found the payout locked, or not findable by the wallet.
        {
            fn unusable(p: &ReleaseProposal, d: &[u8]) -> Result<ReleaseTxView, String> {
                Ok(ReleaseTxView { payout_spendable: false, ..toy_inspect(p, d)? })
            }
            let mut pol = policy();
            pol.inspect = unusable;
            assert_eq!(pol.verify(&duty, &proposal_for(&ev).encode()), reject, "R2 unusable payout");
        }
        // R4: over the per-tx cap (as verify; the actionability screen catches it earlier).
        {
            let big = burn(2_000_000);
            let p = proposal_for(&big);
            assert_eq!(
                policy().verify(&Duty::Release(big), &p.encode()),
                reject,
                "R4 per-tx cap"
            );
        }
    }

    #[test]
    fn inspector_outage_abstains_never_nacks() {
        let ev = burn(1000);
        let p = proposal_for(&ev);
        let mut pol = ReleasePolicy {
            build_tx: toy_build as fn(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
            inspect: (|_p: &ReleaseProposal, _d: &[u8]| Err("daemon RPC down".to_string()))
                as fn(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
            release_gateway: GW.to_string(),
            fees: toy_fees(),
            per_tx_cap: 1_000_000,
        };
        assert_eq!(
            pol.verify(&Duty::Release(ev), &p.encode()),
            ProposalVerdict::Abstain,
            "an outage must not indict an honest leader"
        );
    }

    #[test]
    fn dual_policy_dispatches_by_duty_kind() {
        let mut dual = DualPolicy {
            mint: MintPolicy { contracts: BTreeMap::new() },
            release: policy(),
            cancel: crate::takeover_guard::TakeoverPolicy {
                read: |_: &crate::watch::TakeoverStep| Ok(crate::takeover_guard::TakeoverView::Ended),
            },
            rotate: RotatePolicy { read: |_| Err("no chain".to_string()), contracts: BTreeMap::new(), valid_secs: 3600 },
            handover: HandoverPolicy {
                fetch: |_: &[u8; 32]| Err("no builder".to_string()),
                decode: |_: &[u8]| Err("no daemon".to_string()),
                gateway_id: [0; 32],
            },
        };
        let release = Duty::Release(burn(1000));
        assert!(dual.actionable(&release).is_ok(), "release routed to the release policy");
        let mint = Duty::Mint(crate::watch::MintEvent {
            beldex_txid: [1; 32], output_index: 0,
            dst_chain: ChainId(1),
            to: [0; 20],
            amount: 1,
        });
        assert!(
            matches!(dual.actionable(&mint), Err(BuildError::Unactionable(_))),
            "mint routed to the (empty-registry) mint policy"
        );
        // And build goes to the release side for a release duty.
        assert!(dual.build(&release).is_ok());
    }

    // ---- the flagship: six nodes complete a release autonomously ------------

    struct Node {
        coord: Coordinator<
            TestReleasePolicy,
            fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
            Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
        >,
        orch: Orchestrator,
        net: crate::coordinator::test_support::NodeNet,
        completions: Rc<RefCell<Vec<(DutyKey, Vec<u8>)>>>,
    }

    fn make_node(n: usize, t: usize, index: usize, bus: &Bus) -> Node {
        let completions: Rc<RefCell<Vec<(DutyKey, Vec<u8>)>>> = Rc::new(RefCell::new(Vec::new()));
        let log = completions.clone();
        let mut coord = Coordinator::new(
            committee(n, t),
            index as u16,
            policy(),
            mock_verify,
            mock_sign as fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
            Box::new(move |d: &Duty, proposal: &[u8], sig: &[u8]| {
                // The submitter path decodes the accepted proposal for the blob — prove
                // it decodes and carries the expected fee.
                let p = ReleaseProposal::decode(proposal).expect("accepted proposal decodes");
                assert_eq!(p.fee, FEE);
                log.borrow_mut().push((d.key(), sig.to_vec()));
                ExecOutcome::Submitted
            }) as Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
        );
        coord.sign_settle_steps = 0; // synchronous in-process bus
        Node { coord, orch: Orchestrator::new(), net: bus.node(index), completions }
    }

    #[test]
    fn six_nodes_complete_a_release_autonomously() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();

        // Every node's EVM watcher finalized the same burn. Only the deterministic leader
        // will build a tx; everyone else admits it via R1–R6 and signs the leader's hash.
        for node in &mut nodes {
            node.orch.observe(Duty::Release(burn(1000)));
        }
        for _ in 0..12 {
            for node in &mut nodes {
                node.coord.step(&mut node.orch, &mut node.net);
            }
        }

        let mut sigs = Vec::new();
        for node in &nodes {
            let done = node.completions.borrow();
            assert_eq!(done.len(), 1, "each node completes the release exactly once");
            sigs.push(done[0].1.clone());
            assert_eq!(node.orch.counts(), (0, 0, 1));
        }
        assert!(sigs.iter().all(|s| s == &sigs[0]), "one agreed hash → one agreed aggregate");
        assert!(nodes.iter().all(|nd| nd.coord.live_count() == 0));
    }
}

#[cfg(test)]
mod recipient_shape_tests {
    use super::is_possible_beldex_address;

    /// Every member must reach the same verdict without asking anything, or the ones that
    /// are not the leader keep a session open for a proposal that can never be built.
    #[test]
    fn a_recipient_outside_base58_can_never_be_an_address() {
        // The address a real devnet wallet prints.
        assert!(is_possible_beldex_address(
            b"59sr6Ez6CQKJ7Uq3akAAS7K9jebF1VHnjZtTLXuzjCX5fsiWMsaap2h6uUu4tZUJo4jSxQ8vtGKUvKwpkZB2WKJSQfeRnhJ"
        ));
        // A gateway address, which uses the same alphabet.
        assert!(is_possible_beldex_address(b"gwDJoycVAGzXhAvMFpv47MLgotmPg5bt71JtCNsPkW5E4h9HuboBt2"));

        // The devnet burn that exposed this: hyphens are not base58.
        assert!(!is_possible_beldex_address(b"not-a-real-beldex-address"));
        assert!(!is_possible_beldex_address(b""));
        assert!(!is_possible_beldex_address(&[0xff, 0xfe]));
        // base58 omits these four precisely because they are confusable, and a mistyped
        // address is exactly how they show up.
        for c in [b'0', b'O', b'I', b'l'] {
            let mut a = b"59sr6Ez6CQKJ".to_vec();
            a.push(c);
            assert!(!is_possible_beldex_address(&a), "{} should be rejected", c as char);
        }
    }

    /// Real addresses pass on every network; one mistyped character fails, as do test
    /// placeholders that are base58-clean but were never an address.
    #[cfg(any(feature = "evm-watcher", feature = "tss-integration"))]
    #[test]
    fn a_mistyped_address_fails_its_checksum() {
        use super::has_valid_address_checksum;
        let real: [&[u8]; 3] = [
            // mainnet, testnet (tests/unit_tests/parse_address.cpp), and a devnet wallet
            b"bxda4NxJymoYHRNRh7FjmDCZ912cFsKH7QjJprjNRyXY5Wh2unz1aKq1PPnxKyQBMu5ForNfRkioDGNSi7mqwpnr1KYXQRHfK",
            b"9uDxTecU9r1LuSk12HpU43huCrfR4e7LM6zbvesbHDzCWxzcK9tYKhY2RM9ovD5NrLikxkBa8iakYMcbfC5pZuTc2Vnf1K7",
            b"59sr6Ez6CQKJ7Uq3akAAS7K9jebF1VHnjZtTLXuzjCX5fsiWMsaap2h6uUu4tZUJo4jSxQ8vtGKUvKwpkZB2WKJSQfeRnhJ",
        ];
        for a in real {
            assert!(has_valid_address_checksum(a), "{}", String::from_utf8_lossy(a));
            // One character swapped for another inside the alphabet, at a few positions.
            for pos in [3, 40, a.len() - 2] {
                let mut typo = a.to_vec();
                typo[pos] = if typo[pos] == b'2' { b'3' } else { b'2' };
                assert!(!has_valid_address_checksum(&typo), "typo at {pos} must fail");
            }
            // A dropped character leaves a block of an impossible length or a bad sum.
            assert!(!has_valid_address_checksum(&a[..a.len() - 1]));
        }
        assert!(!has_valid_address_checksum(b"bxRecipient"));
        assert!(!has_valid_address_checksum(b""));
    }
}

#[cfg(test)]
mod rotate_policy_tests {
    use super::*;
    use crate::orchestrator::RotationRequest;

    const C: [u8; 20] = [0xC0; 20];
    const NEW: [u8; 20] = [0x5E; 20];

    fn duty() -> Duty {
        Duty::Rotate(RotationRequest { chain_id: 56, contract: C, new_signer: NEW, new_key_epoch: 4 })
    }

    fn policy(st: RotationState) -> RotatePolicy<impl FnMut(u64) -> Result<RotationState, String>> {
        RotatePolicy { read: move |_| Ok(st), contracts: [(56, C)].into(), valid_secs: 3600 }
    }

    const LIVE: RotationState = RotationState { key_epoch: 3, rotation_nonce: 7, pending_activate_at: 0, now: 1_000_000 };

    #[test]
    fn a_member_signs_the_leaders_hand_off_only_as_it_reads_the_contract() {
        let mut leader = policy(LIVE);
        let p = leader.build(&duty()).unwrap();
        assert_eq!(p, rotate_preimage(56, C, 4, NEW, 8, 1_000_000 + 3600));
        // Read a few seconds later: the same proposal is still the right one.
        let mut member = policy(RotationState { now: 1_000_010, ..LIVE });
        assert_eq!(member.verify(&duty(), &p), ProposalVerdict::Accept);
        assert_eq!(member.signing_message(&duty(), &p), p);

        // Anything else is refused: another signer, a nonce that is not the next, a stale or
        // far-off deadline, another key epoch.
        let reject = ProposalVerdict::Reject(NackReason::PayloadMismatch);
        for bad in [
            rotate_preimage(56, C, 4, [0xBA; 20], 8, 1_003_600),
            rotate_preimage(56, C, 4, NEW, 9, 1_003_600),
            rotate_preimage(56, C, 4, NEW, 8, 1_000_100),
            rotate_preimage(56, C, 4, NEW, 8, 1_000_000 + 3 * 3600),
            rotate_preimage(56, C, 5, NEW, 8, 1_003_600),
        ] {
            assert_eq!(member.verify(&duty(), &bad), reject);
        }
    }

    #[test]
    fn both_preimages_are_the_contracts_abi_encoding() {
        // `cast abi-encode` of the same values: what WrappedBDX keccaks and recovers from.
        let hex = |b: Vec<u8>| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(rotate_preimage(56, C, 4, NEW, 8, 1_003_600)), "1f168494b9c165fdb7617d54f9474d57ca55d8bb4d3f5960fa2e09a81aba1fbd0000000000000000000000000000000000000000000000000000000000000038000000000000000000000000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000000000000000000000000000000000000000000000000000000000040000000000000000000000005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000f5050");
        assert_eq!(hex(activate_preimage(56, C, 4, NEW)), "dde1d75143faf59291dd472ba9226a0604d9eb613b71945f059fbc9365d568040000000000000000000000000000000000000000000000000000000000000038000000000000000000000000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000000000000000000000000000000000000000000000000000000000040000000000000000000000005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e");
    }

    #[test]
    fn no_hand_off_while_the_contract_is_not_ready_for_it() {
        // Already at that epoch, or another rotation pending: nothing to build or sign.
        let done = RotationState { key_epoch: 4, ..LIVE };
        assert!(matches!(policy(done).build(&duty()), Err(BuildError::Unactionable(_))));
        let pending = RotationState { pending_activate_at: 1_000_500, ..LIVE };
        assert!(matches!(policy(pending).build(&duty()), Err(BuildError::Unactionable(_))));
        let p = rotate_preimage(56, C, 4, NEW, 8, 1_003_600);
        assert_eq!(policy(pending).verify(&duty(), &p), ProposalVerdict::Reject(NackReason::PayloadMismatch));
        // A wBDX this node does not serve is never actionable.
        let other = Duty::Rotate(RotationRequest { chain_id: 1, contract: C, new_signer: NEW, new_key_epoch: 4 });
        assert!(policy(LIVE).actionable(&other).is_err());
        // A member that cannot read its own RPC neither signs nor objects.
        let mut blind = RotatePolicy { read: |_| Err("rpc down".to_string()), contracts: [(56, C)].into(), valid_secs: 3600 };
        assert_eq!(blind.verify(&duty(), &p), ProposalVerdict::Abstain);
    }
}

#[cfg(test)]
mod handover_policy_tests {
    use super::*;
    use crate::orchestrator::HandoverRequest;

    const GW: [u8; 32] = [0x6A; 32];
    const NEW: [u8; 32] = [0x9E; 32];

    fn duty() -> Duty {
        Duty::Handover(HandoverRequest { gateway_id: GW, new_owner: NEW, key_epoch: 7 })
    }

    /// The daemon's reading of a blob: here the blob's first byte picks what it says.
    fn view(blob: &[u8]) -> Result<DescriptorUpdateView, String> {
        let honest = DescriptorUpdateView {
            gateway_id: GW,
            owner_key_type: "eddsa".into(),
            owner_key: NEW.to_vec(),
            bridge_reserve: true,
            has_standby: false,
            hash_to_sign: [0x11; 32],
        };
        match blob.first() {
            Some(0) => Ok(honest),
            Some(1) => Ok(DescriptorUpdateView { owner_key: vec![0xBA; 32], ..honest }),
            Some(2) => Ok(DescriptorUpdateView { bridge_reserve: false, ..honest }),
            Some(3) => Ok(DescriptorUpdateView { gateway_id: [0x01; 32], ..honest }),
            Some(4) => Ok(DescriptorUpdateView { owner_key_type: "beldex".into(), ..honest }),
            Some(5) => Ok(DescriptorUpdateView { has_standby: true, ..honest }),
            _ => Err("not a gateway descriptor update".into()),
        }
    }

    fn policy(built: u8) -> HandoverPolicy<impl FnMut(&[u8; 32]) -> Result<Vec<u8>, String>, impl FnMut(&[u8]) -> Result<DescriptorUpdateView, String>> {
        HandoverPolicy { fetch: move |_: &[u8; 32]| Ok(vec![built, 0xAA, 0xBB]), decode: view, gateway_id: GW }
    }

    #[test]
    fn members_sign_only_the_hand_over_their_own_daemon_reads() {
        let mut leader = policy(0);
        let p = leader.build(&duty()).unwrap();
        assert_eq!(&p[..32], &[0x11; 32]);
        assert_eq!(&p[32..], &[0, 0xAA, 0xBB]);
        assert_eq!(policy(0).verify(&duty(), &p), ProposalVerdict::Accept);
        assert_eq!(policy(0).signing_message(&duty(), &p), vec![0x11; 32]);

        let reject = ProposalVerdict::Reject(NackReason::PayloadMismatch);
        // Another owner, the reserve flag dropped, another gateway, another key type, a standby named.
        for bad in 1u8..=5 {
            let blob = [&[0x11u8; 32][..], &[bad, 0xAA, 0xBB][..]].concat();
            assert_eq!(policy(0).verify(&duty(), &blob), reject, "case {bad}");
        }
        // The right update, but a hash that is not the blob's.
        let wrong_hash = [&[0x22u8; 32][..], &[0, 0xAA, 0xBB][..]].concat();
        assert_eq!(policy(0).verify(&duty(), &wrong_hash), reject);
        // A blob this member's daemon cannot read: no judgement either way.
        let unreadable = [&[0x11u8; 32][..], &[9][..]].concat();
        assert_eq!(policy(0).verify(&duty(), &unreadable), ProposalVerdict::Abstain);
    }

    #[test]
    fn a_leader_does_not_propose_what_the_builder_got_wrong() {
        assert!(matches!(policy(1).build(&duty()), Err(BuildError::Transient(_))));
        assert!(matches!(policy(2).build(&duty()), Err(BuildError::Transient(_))));
        // Another committee's gateway is not this policy's to hand over.
        let other = Duty::Handover(HandoverRequest { gateway_id: [0x01; 32], new_owner: NEW, key_epoch: 7 });
        assert!(policy(0).actionable(&other).is_err());
    }
}

//! Standby takeover steps as committee duties.
//!
//! A standby key, named by the live key, may take the bridge over after a delay: that is for
//! a live key that has gone silent. Both committees act through their signers, never a
//! script or a person:
//!  - the live committee cancels any takeover begun against its key while it can sign (on
//!    each wBDX chain `cancelStandbyTakeover(sig)`, on the gateway a standalone cancel over
//!    the daemon's `takeover_cancel_message`). That is the defence against a standby that is
//!    compromised or mistaken.
//!  - the standby committee begins a takeover on every chain once its members each see the
//!    live key failing (a deposit final for the outage window and still unminted), and once
//!    every half is ready completes it on every chain, never one alone.
//!
//! What is signed is fixed by the chain: the contract's preimages on an EVM chain, the
//! daemon's messages on the gateway. So each member rebuilds it from its own view and
//! accepts only an identical proposal (C.5), as for mints. A member whose view does not show
//! that step as due does not sign it.

use crate::coordinator::{BuildError, ProposalPolicy, ProposalVerdict};
use crate::orchestrator::Duty;
use crate::reconcile::DutyReconciler;
use crate::session::NackReason;
use crate::watch::TakeoverStep;

/// What this node reads from its own chain view for a cancel duty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeoverView {
    /// The takeover is running against this committee's live key: the exact bytes to sign.
    Running(Vec<u8>),
    /// That takeover is not running any more (cancelled, completed, or never seen here),
    /// or this committee's key is no longer the live one.
    Ended,
}

/// Signs cancels. `read` asks this node's own RPCs about one cancel duty; an `Err` is a
/// transport failure, which decides nothing.
pub struct TakeoverPolicy<R: FnMut(&TakeoverStep) -> Result<TakeoverView, String>> {
    pub read: R,
}

impl<R: FnMut(&TakeoverStep) -> Result<TakeoverView, String>> ProposalPolicy for TakeoverPolicy<R> {
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Takeover(_) => Ok(()),
            _ => Err(BuildError::Unactionable("not a takeover cancel".into())),
        }
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        let Duty::Takeover(c) = duty else {
            return Err(BuildError::Unactionable("not a takeover cancel".into()));
        };
        match (self.read)(c) {
            Ok(TakeoverView::Running(bytes)) => Ok(bytes),
            Ok(TakeoverView::Ended) => Err(BuildError::Unactionable("the takeover is no longer running".into())),
            Err(e) => Err(BuildError::Transient(e)),
        }
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        let Duty::Takeover(c) = duty else {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        };
        match (self.read)(c) {
            Ok(TakeoverView::Running(bytes)) if bytes == proposal => ProposalVerdict::Accept,
            Ok(TakeoverView::Running(_)) => ProposalVerdict::Reject(NackReason::PayloadMismatch),
            Ok(TakeoverView::Ended) => ProposalVerdict::Reject(NackReason::EventNotObserved),
            // This node cannot tell right now: stay silent, the leader re-proposes.
            Err(_) => ProposalVerdict::Abstain,
        }
    }

    fn signing_message(&self, _duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        // EVM: the preimage (the Pevm signer hashes it, as for a mint). Gateway: the
        // 32-byte message itself.
        proposal.to_vec()
    }
}

/// Settles a cancel duty against the chain: done once that takeover is no longer running.
pub struct TakeoverReconciler<R: FnMut(&TakeoverStep) -> Result<TakeoverView, String>> {
    pub read: R,
}

impl<R: FnMut(&TakeoverStep) -> Result<TakeoverView, String>> DutyReconciler for TakeoverReconciler<R> {
    fn is_settled(&mut self, duty: &Duty) -> Option<bool> {
        let Duty::Takeover(c) = duty else { return Some(false) };
        match (self.read)(c) {
            Ok(TakeoverView::Ended) => Some(true),
            Ok(TakeoverView::Running(_)) => Some(false),
            Err(_) => None,
        }
    }
}

/// The wBDX contract's cancel preimage: `abi.encode(TAKEOVER_CANCEL_TAG, block.chainid,
/// address(this), keyEpoch, takeoverNonce)`. The Pevm signer hashes it with keccak256, as
/// it does a mint preimage, and the contract recovers the live key from that digest.
pub fn evm_cancel_preimage(tag: [u8; 32], chain_id: u64, contract: [u8; 20], key_epoch: u64, nonce: u64) -> Vec<u8> {
    let word_u64 = |x: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&x.to_be_bytes());
        w
    };
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&word_u64(chain_id));
    let mut addr = [0u8; 32];
    addr[12..].copy_from_slice(&contract);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&word_u64(key_epoch));
    out.extend_from_slice(&word_u64(nonce));
    out
}

/// The contract's begin preimage: `abi.encode(TAKEOVER_BEGIN_TAG, block.chainid,
/// address(this), keyEpoch, standbySigner, takeoverNonce + 1)`. The standby key signs it.
pub fn evm_begin_preimage(tag: [u8; 32], chain_id: u64, contract: [u8; 20], key_epoch: u64, standby: [u8; 20], next_nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(192);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&word_u64(chain_id));
    out.extend_from_slice(&word_address(contract));
    out.extend_from_slice(&word_u64(key_epoch));
    out.extend_from_slice(&word_address(standby));
    out.extend_from_slice(&word_u64(next_nonce));
    out
}

/// The contract's complete preimage: `abi.encode(TAKEOVER_COMPLETE_TAG, block.chainid,
/// address(this), keyEpoch + 1, standbySigner)`. The standby key signs it.
pub fn evm_complete_preimage(tag: [u8; 32], chain_id: u64, contract: [u8; 20], next_key_epoch: u64, standby: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&word_u64(chain_id));
    out.extend_from_slice(&word_address(contract));
    out.extend_from_slice(&word_u64(next_key_epoch));
    out.extend_from_slice(&word_address(standby));
    out
}

/// The contract's standby-naming preimage: `abi.encode(STANDBY_TAG, block.chainid,
/// address(this), keyEpoch, newStandby, nonce, deadline)`, nonce `rotationNonce + 1`. The live
/// key signs it.
pub fn evm_set_standby_preimage(
    tag: [u8; 32],
    chain_id: u64,
    contract: [u8; 20],
    key_epoch: u64,
    standby: [u8; 20],
    nonce: u64,
    deadline: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(224);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&word_u64(chain_id));
    out.extend_from_slice(&word_address(contract));
    out.extend_from_slice(&word_u64(key_epoch));
    out.extend_from_slice(&word_address(standby));
    out.extend_from_slice(&word_u64(nonce));
    out.extend_from_slice(&word_u64(deadline));
    out
}

/// The standby, nonce and deadline back from an [`evm_set_standby_preimage`]: what the relayer
/// needs beside the signature.
pub fn evm_set_standby_fields(preimage: &[u8]) -> Option<([u8; 20], u64, u64)> {
    if preimage.len() != 224 {
        return None;
    }
    let u64_at = |w: usize| u64::from_be_bytes(preimage[w * 32 + 24..w * 32 + 32].try_into().expect("8 bytes"));
    let standby: [u8; 20] = preimage[4 * 32 + 12..5 * 32].try_into().ok()?;
    Some((standby, u64_at(5), u64_at(6)))
}

/// The deadline every live member puts in a standby naming: the end of the next whole hour of
/// the chain's clock. Members reading a few seconds apart agree on it (except across an hour
/// boundary, where the next round agrees), and it leaves at least an hour to relay.
pub fn standby_deadline(chain_now: u64) -> u64 {
    (chain_now / 3600 + 2) * 3600
}

fn word_u64(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

fn word_address(a: [u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn evm() -> TakeoverStep {
        TakeoverStep { chain_id: 31337, takeover_id: 3, key_epoch: 2, step: crate::watch::TakeoverStepKind::Cancel }
    }

    #[test]
    fn a_member_signs_only_what_its_own_chain_view_shows() {
        let view = Rc::new(RefCell::new(Ok(TakeoverView::Running(vec![1, 2, 3]))));
        let v = view.clone();
        let mut p = TakeoverPolicy { read: move |_: &TakeoverStep| v.borrow().clone() };
        let d = Duty::Takeover(evm());

        assert!(p.actionable(&d).is_ok());
        assert_eq!(p.build(&d).unwrap(), vec![1, 2, 3]);
        assert_eq!(p.verify(&d, &[1, 2, 3]), ProposalVerdict::Accept);
        assert_eq!(p.verify(&d, &[9]), ProposalVerdict::Reject(NackReason::PayloadMismatch));
        assert_eq!(p.signing_message(&d, &[1, 2, 3]), vec![1, 2, 3]);

        // The takeover ended (or this node never saw it): not signed, not built.
        *view.borrow_mut() = Ok(TakeoverView::Ended);
        assert_eq!(p.verify(&d, &[1, 2, 3]), ProposalVerdict::Reject(NackReason::EventNotObserved));
        assert!(matches!(p.build(&d), Err(BuildError::Unactionable(_))));

        // Its RPC is down: it stays silent rather than guess.
        *view.borrow_mut() = Err("rpc down".into());
        assert_eq!(p.verify(&d, &[1, 2, 3]), ProposalVerdict::Abstain);
        assert!(matches!(p.build(&d), Err(BuildError::Transient(_))));
    }

    #[test]
    fn a_cancel_is_settled_once_its_takeover_is_not_running() {
        let state = Rc::new(RefCell::new(Ok(TakeoverView::Running(vec![7]))));
        let s = state.clone();
        let mut r = TakeoverReconciler { read: move |_: &TakeoverStep| s.borrow().clone() };
        let d = Duty::Takeover(evm());
        assert_eq!(r.is_settled(&d), Some(false));
        *state.borrow_mut() = Ok(TakeoverView::Ended);
        assert_eq!(r.is_settled(&d), Some(true));
        *state.borrow_mut() = Err("rpc down".into());
        assert_eq!(r.is_settled(&d), None, "an unreadable chain decides nothing");
    }

    /// Byte for byte what the contract hashes: abi.encode of the five words (checked against
    /// `cast abi-encode 'f(bytes32,uint256,address,uint64,uint64)' …`).
    #[test]
    fn the_evm_preimage_is_the_contracts_abi_encoding() {
        let pre = evm_cancel_preimage([0x11; 32], 31337, [0x22; 20], 2, 3);
        assert_eq!(pre.len(), 160);
        let hex: String = pre.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            concat!(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0000000000000000000000000000000000000000000000000000000000007a69",
                "0000000000000000000000002222222222222222222222222222222222222222",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
        );
    }

    /// A solvency hold keeps mints and releases waiting. A cancel moves no value and must not
    /// wait: the hold is no time to let a takeover through.
    #[test]
    fn a_cancel_is_signed_while_a_hold_keeps_a_mint_waiting() {
        use crate::chain_registry::ChainId;
        use crate::coordinator::test_support::{committee, mock_sign, mock_verify, Bus};
        use crate::coordinator::{Coordinator, MintPolicy};
        use crate::orchestrator::{DutyKey, ExecOutcome, Orchestrator};
        use crate::release_policy::DualPolicy;
        use crate::transport::Leg;
        use crate::watch::MintEvent;
        use std::collections::BTreeMap;

        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let cancel = TakeoverStep { chain_id: TakeoverStep::GATEWAY, takeover_id: 5, key_epoch: 0, step: crate::watch::TakeoverStepKind::Cancel };
        let mint = MintEvent { beldex_txid: [7; 32], output_index: 0, dst_chain: ChainId(1), to: [3; 20], amount: 10 };
        let mut nodes = Vec::new();
        for i in 0..n {
            let done: Rc<RefCell<Vec<DutyKey>>> = Rc::new(RefCell::new(Vec::new()));
            let log = done.clone();
            let policy = DualPolicy {
                mint: MintPolicy { contracts: BTreeMap::from([(1u64, [0x22u8; 20])]) },
                release: MintPolicy { contracts: BTreeMap::new() },
                cancel: TakeoverPolicy { read: |_: &TakeoverStep| Ok(TakeoverView::Running(vec![0x42; 32])) },
                rotate: MintPolicy { contracts: BTreeMap::new() },
                handover: MintPolicy { contracts: BTreeMap::new() },
            };
            let mut coord = Coordinator::new(
                committee(n, t),
                i as u16,
                policy,
                mock_verify,
                mock_sign as fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
                Box::new(move |d: &Duty, _p: &[u8], _s: &[u8]| {
                    log.borrow_mut().push(d.key());
                    ExecOutcome::Submitted
                }) as Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
            );
            coord.sign_settle_steps = 0;
            coord.hold = Some("wBDX total supply exceeds the gateway's balance".into());
            let mut orch = Orchestrator::new();
            orch.observe(Duty::Mint(mint.clone()));
            orch.observe(Duty::Takeover(cancel));
            nodes.push((coord, orch, bus.node(i), done));
        }
        for _ in 0..30 {
            for (coord, orch, net, _) in nodes.iter_mut() {
                coord.step(orch, net);
            }
        }
        for (_, orch, _, done) in &nodes {
            assert_eq!(*done.borrow(), vec![Duty::Takeover(cancel).key()], "the cancel completes, the mint does not");
            assert_eq!(orch.counts(), (1, 0, 1), "the mint still waits");
        }
    }

    /// Byte for byte cast abi-encode's 'f(bytes32,uint256,address,uint64,address,uint64)' and
    /// 'f(bytes32,uint256,address,uint64,address)' of the same values.
    #[test]
    fn the_begin_and_complete_preimages_are_the_contracts_abi_encoding() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let begin = evm_begin_preimage([0x11; 32], 31337, [0x22; 20], 2, [0x33; 20], 4);
        assert_eq!(
            hex(&begin),
            concat!(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0000000000000000000000000000000000000000000000000000000000007a69",
                "0000000000000000000000002222222222222222222222222222222222222222",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0000000000000000000000003333333333333333333333333333333333333333",
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
        );
        let complete = evm_complete_preimage([0x11; 32], 31337, [0x22; 20], 3, [0x33; 20]);
        assert_eq!(
            hex(&complete),
            concat!(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0000000000000000000000000000000000000000000000000000000000007a69",
                "0000000000000000000000002222222222222222222222222222222222222222",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000003333333333333333333333333333333333333333",
            )
        );
    }

    #[test]
    fn each_takeover_and_key_epoch_is_its_own_duty() {
        let a = evm();
        let b = TakeoverStep { takeover_id: 4, ..a };
        let c = TakeoverStep { key_epoch: 3, ..a };
        let g = TakeoverStep { chain_id: TakeoverStep::GATEWAY, takeover_id: 3, key_epoch: 0, step: crate::watch::TakeoverStepKind::Cancel };
        let keys = [a, b, c, g].map(|x| Duty::Takeover(x).key());
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
        assert_eq!(Duty::Takeover(g).leg(), crate::transport::Leg::Pgw);

        // Begin, complete and cancel of one takeover are three duties, and each survives the
        // round trip through its duty id (how a Done duty is restored after a restart).
        use crate::watch::TakeoverStepKind::{Begin, Cancel, Complete, NameStandby, StandbyAlive};
        let steps = [Cancel, Begin, Complete, NameStandby, StandbyAlive].map(|step| TakeoverStep { step, ..a });
        for i in 0..steps.len() {
            for j in i + 1..steps.len() {
                assert_ne!(Duty::Takeover(steps[i]).key(), Duty::Takeover(steps[j]).key());
            }
        }
        for st in steps {
            assert_eq!(TakeoverStep::from_id(&st.id()), st);
        }
        assert_eq!(Duty::Takeover(a).leg(), crate::transport::Leg::Pevm);
    }

    #[test]
    fn a_standby_naming_preimage_is_the_contracts_encoding_and_gives_its_fields_back() {
        let p = evm_set_standby_preimage([0x11; 32], 31337, [0x22; 20], 3, [0x33; 20], 8, 7200);
        assert_eq!(p.len(), 7 * 32);
        assert_eq!(&p[..32], &[0x11; 32]);
        assert_eq!(&p[4 * 32..4 * 32 + 12], &[0u8; 12], "an address is left-padded");
        assert_eq!(evm_set_standby_fields(&p), Some(([0x33; 20], 8, 7200)));
        assert_eq!(evm_set_standby_fields(&p[..200]), None);
    }

    #[test]
    fn members_reading_within_the_hour_agree_on_the_deadline() {
        assert_eq!(standby_deadline(3600 * 10), 3600 * 12);
        assert_eq!(standby_deadline(3600 * 10 + 3599), 3600 * 12);
        assert_eq!(standby_deadline(3600 * 11), 3600 * 13);
        assert!(standby_deadline(3600 * 10 + 3599) - (3600 * 10 + 3599) > 3600);
    }
}

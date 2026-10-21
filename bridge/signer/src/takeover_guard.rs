//! The live committee's guard against a standby takeover.
//!
//! A standby key, named by the live key, may take the bridge over after a delay. That is
//! for a live key that has gone silent. A key that can still sign proves it is not, by
//! cancelling: on each wBDX chain with `cancelStandbyTakeover(sig)`, and on the Beldex
//! gateway with a standalone cancel signed over the daemon's `takeover_cancel_message`.
//! Every live signer watches for a begin and opens a cancel duty; the committee signs it
//! like a mint or a release. This is the defence against a standby that is compromised or
//! mistaken, so it never waits on a person or a script.
//!
//! What is signed is fixed by the chain: on an EVM chain the contract's cancel preimage
//! (`TAKEOVER_CANCEL_TAG`, chain id, contract, key epoch, takeover nonce), on the gateway the
//! 32-byte message the daemon reports. So each member rebuilds it from its own view and
//! accepts only an identical proposal (C.5), as for mints. A member reading a different
//! takeover, or none, does not sign.

use crate::coordinator::{BuildError, ProposalPolicy, ProposalVerdict};
use crate::orchestrator::Duty;
use crate::reconcile::DutyReconciler;
use crate::session::NackReason;
use crate::watch::TakeoverCancel;

/// What this node reads from its own chain view for a cancel duty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelView {
    /// The takeover is running against this committee's live key: the exact bytes to sign.
    Running(Vec<u8>),
    /// That takeover is not running any more (cancelled, completed, or never seen here),
    /// or this committee's key is no longer the live one.
    Ended,
}

/// Signs cancels. `read` asks this node's own RPCs about one cancel duty; an `Err` is a
/// transport failure, which decides nothing.
pub struct CancelPolicy<R: FnMut(&TakeoverCancel) -> Result<CancelView, String>> {
    pub read: R,
}

impl<R: FnMut(&TakeoverCancel) -> Result<CancelView, String>> ProposalPolicy for CancelPolicy<R> {
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Cancel(_) => Ok(()),
            _ => Err(BuildError::Unactionable("not a takeover cancel".into())),
        }
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        let Duty::Cancel(c) = duty else {
            return Err(BuildError::Unactionable("not a takeover cancel".into()));
        };
        match (self.read)(c) {
            Ok(CancelView::Running(bytes)) => Ok(bytes),
            Ok(CancelView::Ended) => Err(BuildError::Unactionable("the takeover is no longer running".into())),
            Err(e) => Err(BuildError::Transient(e)),
        }
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        let Duty::Cancel(c) = duty else {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        };
        match (self.read)(c) {
            Ok(CancelView::Running(bytes)) if bytes == proposal => ProposalVerdict::Accept,
            Ok(CancelView::Running(_)) => ProposalVerdict::Reject(NackReason::PayloadMismatch),
            Ok(CancelView::Ended) => ProposalVerdict::Reject(NackReason::EventNotObserved),
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
pub struct CancelReconciler<R: FnMut(&TakeoverCancel) -> Result<CancelView, String>> {
    pub read: R,
}

impl<R: FnMut(&TakeoverCancel) -> Result<CancelView, String>> DutyReconciler for CancelReconciler<R> {
    fn is_settled(&mut self, duty: &Duty) -> Option<bool> {
        let Duty::Cancel(c) = duty else { return Some(false) };
        match (self.read)(c) {
            Ok(CancelView::Ended) => Some(true),
            Ok(CancelView::Running(_)) => Some(false),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn evm() -> TakeoverCancel {
        TakeoverCancel { chain_id: 31337, takeover_id: 3, key_epoch: 2 }
    }

    #[test]
    fn a_member_signs_only_what_its_own_chain_view_shows() {
        let view = Rc::new(RefCell::new(Ok(CancelView::Running(vec![1, 2, 3]))));
        let v = view.clone();
        let mut p = CancelPolicy { read: move |_: &TakeoverCancel| v.borrow().clone() };
        let d = Duty::Cancel(evm());

        assert!(p.actionable(&d).is_ok());
        assert_eq!(p.build(&d).unwrap(), vec![1, 2, 3]);
        assert_eq!(p.verify(&d, &[1, 2, 3]), ProposalVerdict::Accept);
        assert_eq!(p.verify(&d, &[9]), ProposalVerdict::Reject(NackReason::PayloadMismatch));
        assert_eq!(p.signing_message(&d, &[1, 2, 3]), vec![1, 2, 3]);

        // The takeover ended (or this node never saw it): not signed, not built.
        *view.borrow_mut() = Ok(CancelView::Ended);
        assert_eq!(p.verify(&d, &[1, 2, 3]), ProposalVerdict::Reject(NackReason::EventNotObserved));
        assert!(matches!(p.build(&d), Err(BuildError::Unactionable(_))));

        // Its RPC is down: it stays silent rather than guess.
        *view.borrow_mut() = Err("rpc down".into());
        assert_eq!(p.verify(&d, &[1, 2, 3]), ProposalVerdict::Abstain);
        assert!(matches!(p.build(&d), Err(BuildError::Transient(_))));
    }

    #[test]
    fn a_cancel_is_settled_once_its_takeover_is_not_running() {
        let state = Rc::new(RefCell::new(Ok(CancelView::Running(vec![7]))));
        let s = state.clone();
        let mut r = CancelReconciler { read: move |_: &TakeoverCancel| s.borrow().clone() };
        let d = Duty::Cancel(evm());
        assert_eq!(r.is_settled(&d), Some(false));
        *state.borrow_mut() = Ok(CancelView::Ended);
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
        let cancel = TakeoverCancel { chain_id: TakeoverCancel::GATEWAY, takeover_id: 5, key_epoch: 0 };
        let mint = MintEvent { beldex_txid: [7; 32], output_index: 0, dst_chain: ChainId(1), to: [3; 20], amount: 10 };
        let mut nodes = Vec::new();
        for i in 0..n {
            let done: Rc<RefCell<Vec<DutyKey>>> = Rc::new(RefCell::new(Vec::new()));
            let log = done.clone();
            let policy = DualPolicy {
                mint: MintPolicy { contracts: BTreeMap::from([(1u64, [0x22u8; 20])]) },
                release: MintPolicy { contracts: BTreeMap::new() },
                cancel: CancelPolicy { read: |_: &TakeoverCancel| Ok(CancelView::Running(vec![0x42; 32])) },
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
            orch.observe(Duty::Cancel(cancel));
            nodes.push((coord, orch, bus.node(i), done));
        }
        for _ in 0..30 {
            for (coord, orch, net, _) in nodes.iter_mut() {
                coord.step(orch, net);
            }
        }
        for (_, orch, _, done) in &nodes {
            assert_eq!(*done.borrow(), vec![Duty::Cancel(cancel).key()], "the cancel completes, the mint does not");
            assert_eq!(orch.counts(), (1, 0, 1), "the mint still waits");
        }
    }

    #[test]
    fn each_takeover_and_key_epoch_is_its_own_duty() {
        let a = evm();
        let b = TakeoverCancel { takeover_id: 4, ..a };
        let c = TakeoverCancel { key_epoch: 3, ..a };
        let g = TakeoverCancel { chain_id: TakeoverCancel::GATEWAY, takeover_id: 3, key_epoch: 0 };
        let keys = [a, b, c, g].map(|x| Duty::Cancel(x).key());
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
        assert_eq!(Duty::Cancel(g).leg(), crate::transport::Leg::Pgw);
        assert_eq!(Duty::Cancel(a).leg(), crate::transport::Leg::Pevm);
    }
}

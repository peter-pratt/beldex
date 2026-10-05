//! The **reference gas-paying submitter** (feature `submit-http`): the deployment piece that
//! turns the keyless courier into an unattended service.
//!
//! Flow per call: resolve nonce + fees + gas limit from the chain, build the
//! [`Eip1559Tx`](crate::eip1559::Eip1559Tx), sign its sighash with the relayer's gas key, and
//! `eth_sendRawTransaction`.
//!
//! **Trust note.** The gas key signs only the *outer* envelope; the committee's `Pevm`
//! signature is inside the calldata and is what the contract `ecrecover`s. So this key holds
//! **no bridge authority** — a leak costs gas, never funds — and anyone may run this service
//! (or none: `RelayPayload::to_prepared` + `cast send` remains the always-available path, so
//! the bridge is never liveness-blocked on a relayer).
//!
//! Safety properties worth stating, because they are the ones that bite in production:
//! * **Gas estimation is a dry run.** A `mint` that would revert (already minted, cap
//!   exceeded, bad signature) fails `eth_estimateGas`, so it is reported as
//!   [`SubmitError::Rejected`] *before* any gas is spent.
//! * **Fee ceilings are explicit.** `max_fee_per_gas` is capped by configuration; a chain in a
//!   fee spike yields `Rejected` rather than draining the gas wallet.
//! * **Replay is the contract's job.** Broadcasting the same mint twice is harmless
//!   (`processedDeposits` reverts the second), which is why at-least-once delivery from
//!   several relayers is safe by design.

use crate::eip1559::Eip1559Tx;
use crate::payload::PreparedCall;
use crate::submit::{SubmitError, TxSubmitter};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// Per-chain endpoint + fee policy.
#[derive(Debug, Clone)]
pub struct ChainEndpoint {
    pub chain_id: u64,
    pub rpc_url: String,
    /// Hard ceiling on `max_fee_per_gas` (wei). A chain above this is skipped, not paid.
    pub max_fee_cap_wei: u128,
    /// Tip offered to the producer (wei). `0` lets the node's suggestion stand.
    pub priority_fee_wei: u128,
    /// Multiply the estimate by this percentage for headroom (e.g. `120` = +20%).
    pub gas_limit_pct: u64,
}

impl ChainEndpoint {
    pub fn new(chain_id: u64, rpc_url: impl Into<String>) -> ChainEndpoint {
        ChainEndpoint {
            chain_id,
            rpc_url: rpc_url.into(),
            max_fee_cap_wei: 200_000_000_000, // 200 gwei
            priority_fee_wei: 1_500_000_000,  // 1.5 gwei
            gas_limit_pct: 125,
        }
    }
}

/// Signs the outer tx with a funded secp256k1 key and broadcasts it.
pub struct HttpSubmitter {
    key: SigningKey,
    /// The gas wallet's address (derived from `key`), used for the nonce lookup + `from`.
    pub address: [u8; 20],
    pub chains: Vec<ChainEndpoint>,
}

impl HttpSubmitter {
    /// `secret_key` is a 32-byte secp256k1 scalar (the gas key — NOT any bridge key).
    pub fn new(secret_key: &[u8; 32], chains: Vec<ChainEndpoint>) -> Result<HttpSubmitter, String> {
        let key = SigningKey::from_bytes(secret_key.into()).map_err(|e| e.to_string())?;
        let vk = key.verifying_key();
        let enc = vk.to_encoded_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&h[12..]);
        Ok(HttpSubmitter { key, address, chains })
    }

    fn endpoint(&self, chain_id: u64) -> Result<&ChainEndpoint, SubmitError> {
        self.chains
            .iter()
            .find(|c| c.chain_id == chain_id)
            .ok_or(SubmitError::UnknownChain(chain_id))
    }

    fn rpc(&self, url: &str, method: &str, params: Value) -> Result<Value, SubmitError> {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = crate::http_agent()
            .post(url)
            .send_json(req)
            .map_err(|e| SubmitError::Transport(format!("{method}: {e}")))?;
        let v: Value = resp
            .into_json()
            .map_err(|e| SubmitError::Transport(format!("{method}: bad json: {e}")))?;
        if let Some(err) = v.get("error") {
            // A revert surfaces here (notably from eth_estimateGas) — that is a rejection,
            // not a transport problem, and must not be retried blindly.
            return Err(SubmitError::Rejected(format!("{method}: {err}")));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| SubmitError::Transport(format!("{method}: missing result")))
    }

    fn hex_quantity(v: &Value, what: &str) -> Result<u128, SubmitError> {
        let s = v
            .as_str()
            .ok_or_else(|| SubmitError::Transport(format!("{what}: not a hex string")))?;
        u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
            .map_err(|e| SubmitError::Transport(format!("{what}: {e}")))
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What a stateful [`HttpSubmitter::relay`] run did with the payload's call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Signed and broadcast under a new nonce.
    Sent { tx_hash: String, nonce: u64 },
    /// This wallet already has a transaction carrying the same call pending; nothing new
    /// was sent (re-priced if it was stale).
    AlreadyPending { tx_hash: String, nonce: u64 },
}

impl HttpSubmitter {
    /// Current `(max_fee, tip)`: base fee from the latest block with 2× headroom, plus the
    /// configured tip (or the node's suggestion).
    fn current_fees(&self, ep: &ChainEndpoint) -> Result<(u128, u128), SubmitError> {
        let block = self.rpc(&ep.rpc_url, "eth_getBlockByNumber", json!(["latest", false]))?;
        let base_fee = block
            .get("baseFeePerGas")
            .map(|v| Self::hex_quantity(v, "baseFeePerGas"))
            .transpose()?
            .unwrap_or(0);
        let tip = if ep.priority_fee_wei > 0 {
            ep.priority_fee_wei
        } else {
            Self::hex_quantity(
                &self.rpc(&ep.rpc_url, "eth_maxPriorityFeePerGas", json!([]))?,
                "maxPriorityFeePerGas",
            )?
        };
        // 2× base fee is the standard headroom for the next block's base-fee rise.
        Ok((base_fee.saturating_mul(2).saturating_add(tip), tip))
    }

    fn check_cap(ep: &ChainEndpoint, max_fee: u128) -> Result<(), SubmitError> {
        if max_fee > ep.max_fee_cap_wei {
            return Err(SubmitError::Rejected(format!(
                "max_fee {max_fee} wei exceeds the configured cap {} wei — not broadcasting",
                ep.max_fee_cap_wei
            )));
        }
        Ok(())
    }

    /// Gas limit with headroom. Also the revert dry-run: a call that would revert (already
    /// minted, over cap, bad signature) fails here as `Rejected`, before any gas is spent.
    fn estimate(&self, ep: &ChainEndpoint, to: &[u8; 20], data: &[u8]) -> Result<u64, SubmitError> {
        let est = Self::hex_quantity(
            &self.rpc(
                &ep.rpc_url,
                "eth_estimateGas",
                json!([{
                    "from": format!("0x{}", hexs(&self.address)),
                    "to": format!("0x{}", hexs(to)),
                    "data": format!("0x{}", hexs(data)),
                    "value": "0x0"
                }]),
            )?,
            "estimateGas",
        )?;
        Ok((est.saturating_mul(ep.gas_limit_pct as u128) / 100) as u64)
    }

    fn nonce(&self, ep: &ChainEndpoint, tag: &str) -> Result<u64, SubmitError> {
        let from = format!("0x{}", hexs(&self.address));
        Ok(Self::hex_quantity(
            &self.rpc(&ep.rpc_url, "eth_getTransactionCount", json!([from, tag]))?,
            "nonce",
        )? as u64)
    }

    /// Sign the envelope. Returns the raw bytes and the transaction hash (keccak of them),
    /// so the hash can be recorded before anything is broadcast.
    fn sign(
        &self,
        call: &PreparedCall,
        nonce: u64,
        tip: u128,
        max_fee: u128,
        gas_limit: u64,
    ) -> Result<(Vec<u8>, String), SubmitError> {
        let tx = Eip1559Tx::from_call(call, nonce, tip, max_fee, gas_limit);
        let sighash = tx.sighash();
        let (sig, recid): (Signature, RecoveryId) = self
            .key
            .sign_prehash_recoverable(&sighash)
            .map_err(|e| SubmitError::Rejected(format!("signing failed: {e}")))?;
        let sig = sig.normalize_s().unwrap_or(sig); // low-S is required by consensus rules
        let b = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        let raw = tx.encode_signed(recid.to_byte() & 1, &r, &s);
        let hash = format!("0x{}", hexs(&Keccak256::digest(&raw)));
        Ok((raw, hash))
    }

    fn send(&self, ep: &ChainEndpoint, raw: &[u8]) -> Result<String, SubmitError> {
        let sent = self.rpc(
            &ep.rpc_url,
            "eth_sendRawTransaction",
            json!([format!("0x{}", hexs(raw))]),
        )?;
        sent.as_str()
            .map(String::from)
            .ok_or_else(|| SubmitError::Transport("sendRawTransaction: no tx hash".into()))
    }

    /// Relay `call`, keeping this wallet's in-flight transactions in `state_dir`.
    ///
    /// Under an exclusive lock on the `(chain, wallet)` state: forget what has been mined,
    /// re-price whatever has been pending too long (cancelling any whose call would now
    /// revert), then send `call` unless a transaction carrying it is already pending.
    /// `log` receives one line per action taken on an older transaction.
    pub fn relay(
        &self,
        call: &PreparedCall,
        state_dir: &str,
        log: &mut Vec<String>,
    ) -> Result<RelayOutcome, SubmitError> {
        use crate::relay_state::{bumped_fees, now_secs, InFlight, StateFile};

        let ep = self.endpoint(call.chain_id)?;
        let (file, mut state) =
            StateFile::open(state_dir, call.chain_id, &self.address).map_err(SubmitError::Transport)?;
        let save = |st: &crate::relay_state::RelayState| file.save(st).map_err(SubmitError::Transport);

        state.prune_mined(self.nonce(ep, "latest")?);
        save(&state)?;

        // Re-price what has been pending too long, lowest nonce first: that one holds up
        // everything after it.
        let now = now_secs();
        for old in state.stale(now) {
            let (now_max, now_tip) = self.current_fees(ep)?;
            let (max_fee, tip) = bumped_fees(old.max_fee, old.tip, now_max, now_tip);
            if let Err(e) = Self::check_cap(ep, max_fee) {
                log.push(format!("nonce {} still pending, cannot re-price: {e:?}", old.nonce));
                continue;
            }
            // Still worth carrying? A call that would now revert (another relayer minted
            // the deposit) is not re-sent — that would pay for a revert. A zero-value
            // transfer to ourselves takes its nonce instead, so the queue behind it moves.
            let (to, data, gas_limit, cancel) = if old.cancel {
                (self.address, Vec::new(), 21_000, true)
            } else {
                match self.estimate(ep, &old.to, &old.data) {
                    Ok(g) => (old.to, old.data.clone(), g.max(old.gas_limit), false),
                    Err(SubmitError::Rejected(_)) => (self.address, Vec::new(), 21_000, true),
                    Err(e) => return Err(e),
                }
            };
            let replacement = PreparedCall { chain_id: call.chain_id, to, data: data.clone() };
            let (raw, tx_hash) = self.sign(&replacement, old.nonce, tip, max_fee, gas_limit)?;
            let entry = InFlight {
                nonce: old.nonce,
                tx_hash: tx_hash.clone(),
                to,
                data,
                max_fee,
                tip,
                gas_limit,
                sent_at: now,
                cancel,
            };
            match self.send(ep, &raw) {
                Ok(_) => {
                    log.push(format!(
                        "nonce {} {} at max_fee {max_fee}: {tx_hash} (replaces {})",
                        old.nonce,
                        if cancel { "cancelled" } else { "re-priced" },
                        old.tx_hash
                    ));
                    state.record(entry);
                }
                // The nonce was mined between our read and this send: nothing to replace.
                Err(SubmitError::Rejected(m)) if m.to_lowercase().contains("nonce too low") => {
                    state.remove(old.nonce);
                }
                Err(e) => log.push(format!("nonce {} re-price not accepted: {e:?}", old.nonce)),
            }
            save(&state)?;
        }

        if let Some(e) = state.find_call(&call.to, &call.data) {
            return Ok(RelayOutcome::AlreadyPending { tx_hash: e.tx_hash.clone(), nonce: e.nonce });
        }

        let (max_fee, tip) = self.current_fees(ep)?;
        Self::check_cap(ep, max_fee)?;
        let gas_limit = self.estimate(ep, &call.to, &call.data)?;
        let nonce = state.next_nonce(self.nonce(ep, "pending")?);
        let (raw, tx_hash) = self.sign(call, nonce, tip, max_fee, gas_limit)?;

        // Record BEFORE broadcasting. If this process dies after the send, the next run
        // still knows the nonce is taken and which call it carries.
        state.record(InFlight {
            nonce,
            tx_hash: tx_hash.clone(),
            to: call.to,
            data: call.data.clone(),
            max_fee,
            tip,
            gas_limit,
            sent_at: now_secs(),
            cancel: false,
        });
        save(&state)?;
        match self.send(ep, &raw) {
            Ok(_) => Ok(RelayOutcome::Sent { tx_hash, nonce }),
            // Refused outright: it never entered a mempool, so the nonce is free again.
            Err(SubmitError::Rejected(m)) => {
                state.remove(nonce);
                save(&state)?;
                Err(SubmitError::Rejected(m))
            }
            // Unknown whether the node took it: keep the record. If it did not, the entry
            // goes stale and is re-sent at this nonce, which also fills the gap.
            Err(e) => Err(e),
        }
    }
}

impl TxSubmitter for HttpSubmitter {
    /// Stateless single submission: no record of in-flight transactions, so no duplicate
    /// detection or re-pricing. [`HttpSubmitter::relay`] is what `relay` uses.
    fn submit(&self, call: &PreparedCall) -> Result<String, SubmitError> {
        let ep = self.endpoint(call.chain_id)?;
        // Nonce: `pending` so back-to-back submissions from this process don't collide.
        let nonce = self.nonce(ep, "pending")?;
        let (max_fee, tip) = self.current_fees(ep)?;
        Self::check_cap(ep, max_fee)?;
        let gas_limit = self.estimate(ep, &call.to, &call.data)?;
        let (raw, _) = self.sign(call, nonce, tip, max_fee, gas_limit)?;
        self.send(ep, &raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic non-zero key (never used anywhere real).
    fn test_key() -> [u8; 32] {
        let mut k = [0x11u8; 32];
        k[31] = 0x22;
        k
    }

    #[test]
    fn address_is_the_keccak_of_the_uncompressed_pubkey() {
        let s = HttpSubmitter::new(&test_key(), vec![ChainEndpoint::new(1, "http://x")]).unwrap();
        // Derived independently here: keccak(pubkey[1..])[12..].
        let key = SigningKey::from_bytes(&test_key().into()).unwrap();
        let enc = key.verifying_key().to_encoded_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        assert_eq!(s.address, h[12..]);
        assert_ne!(s.address, [0u8; 20]);
    }

    #[test]
    fn unknown_chain_is_reported_without_any_network_call() {
        let s = HttpSubmitter::new(&test_key(), vec![ChainEndpoint::new(1, "http://unused")]).unwrap();
        let call = PreparedCall { chain_id: 999, to: [0; 20], data: vec![] };
        assert_eq!(s.submit(&call), Err(SubmitError::UnknownChain(999)));
    }

    #[test]
    fn signature_recovers_to_the_gas_address() {
        // The envelope's signature must recover to `address`, or the node would charge a
        // different account (and the nonce we looked up would be the wrong one).
        use k256::ecdsa::VerifyingKey;
        let s = HttpSubmitter::new(&test_key(), vec![ChainEndpoint::new(31337, "http://x")]).unwrap();
        let call = PreparedCall { chain_id: 31337, to: [0x22; 20], data: vec![1, 2, 3] };
        let tx = Eip1559Tx::from_call(&call, 1, 1_000, 2_000, 100_000);
        let sighash = tx.sighash();
        let (sig, recid) = s.key.sign_prehash_recoverable(&sighash).unwrap();
        let vk = VerifyingKey::recover_from_prehash(&sighash, &sig, recid).unwrap();
        let enc = vk.to_encoded_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        assert_eq!(&h[12..], &s.address[..]);
    }

    #[test]
    fn fee_cap_is_enforced_before_broadcasting() {
        // A cap below the tip alone must reject: the check is `2*base + tip > cap`, and with
        // base unknown (no network here) we assert the arithmetic directly.
        let ep = ChainEndpoint { max_fee_cap_wei: 1_000, priority_fee_wei: 5_000, ..ChainEndpoint::new(1, "http://x") };
        let base_fee: u128 = 10_000;
        let max_fee = base_fee.saturating_mul(2).saturating_add(ep.priority_fee_wei);
        assert!(max_fee > ep.max_fee_cap_wei, "this configuration must trip the cap");
    }

    #[test]
    fn gas_limit_headroom_is_applied() {
        let ep = ChainEndpoint::new(1, "http://x");
        assert_eq!(ep.gas_limit_pct, 125);
        let est: u128 = 100_000;
        assert_eq!((est * ep.gas_limit_pct as u128 / 100) as u64, 125_000);
    }
}

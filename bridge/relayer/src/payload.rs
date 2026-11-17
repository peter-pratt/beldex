//! The unit of work a relayer carries: a **[`RelayPayload`]** — an already-committee-signed
//! wBDX call, fully self-contained. The relayer turns it into a [`PreparedCall`] (the exact
//! `{chain_id, to, data}` to broadcast) and either pays gas to submit it or hands it to the
//! user to submit themselves. The relayer verifies nothing and can forge nothing: the
//! authorizing signature is already inside the payload, and the destination contract checks
//! it. If every relayer vanishes, any user can build the same [`PreparedCall`] and broadcast.

use crate::abi::{
    build_activate_calldata, build_mint_calldata, build_rotate_calldata, build_set_standby_calldata,
    build_takeover_calldata, BEGIN_TAKEOVER_SELECTOR, CANCEL_TAKEOVER_SELECTOR, COMPLETE_TAKEOVER_SELECTOR,
};

/// Which step of a standby takeover a [`RelayPayload::TakeoverStep`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverStepKind {
    /// The standby committee starts the clock (`beginStandbyTakeover`).
    Begin,
    /// After the delay, the standby committee takes over (`completeStandbyTakeover`).
    Complete,
    /// The live committee, still able to sign, stops it (`cancelStandbyTakeover`).
    Cancel,
}

impl TakeoverStepKind {
    fn json_kind(self) -> &'static str {
        match self {
            TakeoverStepKind::Begin => "takeover_begin",
            TakeoverStepKind::Complete => "takeover_complete",
            TakeoverStepKind::Cancel => "takeover_cancel",
        }
    }
    fn selector(self) -> [u8; 4] {
        match self {
            TakeoverStepKind::Begin => BEGIN_TAKEOVER_SELECTOR,
            TakeoverStepKind::Complete => COMPLETE_TAKEOVER_SELECTOR,
            TakeoverStepKind::Cancel => CANCEL_TAKEOVER_SELECTOR,
        }
    }
}

/// A ready-to-broadcast EVM call: send `data` to `to` on chain `chain_id`, paying gas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCall {
    pub chain_id: u64,
    pub to: [u8; 20],
    pub data: Vec<u8>,
}

/// An already-signed wBDX payload a relayer carries to its destination chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPayload {
    /// A committee-signed `mint` (a finalized Beldex deposit → wBDX on `chain_id`).
    Mint {
        contract: [u8; 20],
        chain_id: u64,
        to: [u8; 20],
        amount: u128,
        beldex_txid: [u8; 32],
        /// Which gateway output of `beldex_txid` this mint discharges.
        output_index: u32,
        /// The `Pevm` committee ECDSA signature (r‖s‖v, 65 bytes) — verified by `ecrecover`.
        sig: Vec<u8>,
    },
    /// An outgoing-committee-signed `rotateSigner` (the H.6 key hand-off).
    Rotate {
        contract: [u8; 20],
        chain_id: u64,
        new_signer: [u8; 20],
        new_key_epoch: u64,
        /// Single-use authorization number; the contract requires `rotationNonce + 1`.
        nonce: u64,
        /// Last timestamp at which this authorization may be relayed.
        deadline: u128,
        sig: Vec<u8>,
    },
    /// A step of a standby takeover: the standby committee's begin or complete, or the live
    /// committee's cancel. The contract binds each signature to the takeover's nonce and the
    /// key epoch, so a relayer can carry it and do nothing else with it.
    TakeoverStep { step: TakeoverStepKind, contract: [u8; 20], chain_id: u64, sig: Vec<u8> },
    /// The live committee names its standby (`setStandby`): single-use (`rotationNonce + 1`)
    /// and expiring, like a rotation.
    SetStandby {
        contract: [u8; 20],
        chain_id: u64,
        standby: [u8; 20],
        nonce: u64,
        deadline: u128,
        sig: Vec<u8>,
    },
    /// An incoming-committee-signed `activateRotation`, sendable once the challenge window
    /// of the pending rotation has passed (before that the gas estimate reverts and nothing
    /// is spent). Only `sig` goes on chain; the pending signer and epoch it was signed for
    /// say which rotation it completes.
    Activate {
        contract: [u8; 20],
        chain_id: u64,
        pending_signer: [u8; 20],
        pending_key_epoch: u64,
        sig: Vec<u8>,
    },
}

impl RelayPayload {
    pub fn chain_id(&self) -> u64 {
        match self {
            RelayPayload::Mint { chain_id, .. }
            | RelayPayload::Rotate { chain_id, .. }
            | RelayPayload::TakeoverStep { chain_id, .. }
            | RelayPayload::SetStandby { chain_id, .. }
            | RelayPayload::Activate { chain_id, .. } => *chain_id,
        }
    }

    pub fn contract(&self) -> [u8; 20] {
        match self {
            RelayPayload::Mint { contract, .. }
            | RelayPayload::Rotate { contract, .. }
            | RelayPayload::TakeoverStep { contract, .. }
            | RelayPayload::SetStandby { contract, .. }
            | RelayPayload::Activate { contract, .. } => *contract,
        }
    }

    /// The ABI calldata for this payload's wBDX call.
    pub fn calldata(&self) -> Vec<u8> {
        match self {
            RelayPayload::Mint { to, amount, beldex_txid, output_index, sig, .. } => {
                build_mint_calldata(*to, *amount, *beldex_txid, *output_index, sig)
            }
            RelayPayload::Rotate { new_signer, new_key_epoch, nonce, deadline, sig, .. } => {
                build_rotate_calldata(*new_signer, *new_key_epoch, *nonce, *deadline, sig)
            }
            RelayPayload::TakeoverStep { step, sig, .. } => build_takeover_calldata(step.selector(), sig),
            RelayPayload::SetStandby { standby, nonce, deadline, sig, .. } => {
                build_set_standby_calldata(*standby, *nonce, *deadline, sig)
            }
            RelayPayload::Activate { sig, .. } => build_activate_calldata(sig),
        }
    }

    /// The exact `{chain_id, to, data}` to broadcast (or hand to `cast send` / a wallet).
    pub fn to_prepared(&self) -> PreparedCall {
        PreparedCall { chain_id: self.chain_id(), to: self.contract(), data: self.calldata() }
    }
}

/// Payload decode/parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    MissingField(&'static str),
    BadHex(&'static str),
    BadLength(&'static str),
    BadAmount,
    /// A numeric field outside the range it is carried in.
    OutOfRange(&'static str),
    UnknownKind(String),
    Json(String),
}

/// Decode a fixed-size hex field (no `0x`), erroring with the field name.
fn hex_fixed<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], PayloadError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|_| PayloadError::BadHex(field))?;
    if bytes.len() != N {
        return Err(PayloadError::BadLength(field));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_var(s: &str, field: &'static str) -> Result<Vec<u8>, PayloadError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| PayloadError::BadHex(field))
}

#[cfg(feature = "json")]
mod json {
    use super::*;
    use serde_json::Value;

    fn get_str<'a>(v: &'a Value, field: &'static str) -> Result<&'a str, PayloadError> {
        v.get(field).and_then(Value::as_str).ok_or(PayloadError::MissingField(field))
    }

    impl RelayPayload {
        /// Parse a payload from the JSON a signer (or a user) hands to the relayer:
        ///
        /// ```json
        /// { "kind": "mint", "contract": "<40hex>", "chain_id": 1, "to": "<40hex>",
        ///   "amount": "1000", "beldex_txid": "<64hex>", "sig": "<130hex>" }
        /// { "kind": "rotate", "contract": "<40hex>", "chain_id": 1,
        ///   "new_signer": "<40hex>", "new_key_epoch": 7, "sig": "<130hex>" }
        /// { "kind": "takeover_begin" | "takeover_complete" | "takeover_cancel",
        ///   "contract": "<40hex>", "chain_id": 1, "sig": "<130hex>" }
        /// { "kind": "set_standby", "contract": "<40hex>", "chain_id": 1,
        ///   "standby": "<40hex>", "nonce": 3, "deadline": "<decimal>", "sig": "<130hex>" }
        /// { "kind": "activate", "contract": "<40hex>", "chain_id": 1,
        ///   "pending_signer": "<40hex>", "pending_key_epoch": 7, "sig": "<130hex>" }
        /// ```
        ///
        /// `amount` is a decimal **string** (a wBDX unit is 1 atomic BDX; u128 to be safe).
        pub fn from_json(s: &str) -> Result<RelayPayload, PayloadError> {
            let v: Value = serde_json::from_str(s).map_err(|e| PayloadError::Json(e.to_string()))?;
            let kind = get_str(&v, "kind")?;
            // Reject an unknown kind BEFORE parsing shared fields, so a bad kind
            // surfaces as UnknownKind rather than a field error on contract/sig.
            let step = match kind {
                "takeover_begin" => Some(TakeoverStepKind::Begin),
                "takeover_complete" => Some(TakeoverStepKind::Complete),
                "takeover_cancel" => Some(TakeoverStepKind::Cancel),
                _ => None,
            };
            if kind != "mint" && kind != "rotate" && kind != "set_standby" && kind != "activate" && step.is_none() {
                return Err(PayloadError::UnknownKind(kind.to_string()));
            }
            let chain_id = v.get("chain_id").and_then(Value::as_u64).ok_or(PayloadError::MissingField("chain_id"))?;
            let contract = hex_fixed::<20>(get_str(&v, "contract")?, "contract")?;
            let sig = hex_var(get_str(&v, "sig")?, "sig")?;

            match kind {
                "mint" => {
                    let to = hex_fixed::<20>(get_str(&v, "to")?, "to")?;
                    let beldex_txid = hex_fixed::<32>(get_str(&v, "beldex_txid")?, "beldex_txid")?;
                    let amount = get_str(&v, "amount")?
                        .parse::<u128>()
                        .map_err(|_| PayloadError::BadAmount)?;
                    // Required, and never truncated: it is part of the signed mint tuple and
                    // the contract's replay key, so a missing or wrapped value would name a
                    // different deposit output (and the signature would not verify for it).
                    let output_index = v
                        .get("output_index")
                        .and_then(Value::as_u64)
                        .ok_or(PayloadError::MissingField("output_index"))?;
                    let output_index =
                        u32::try_from(output_index).map_err(|_| PayloadError::OutOfRange("output_index"))?;
                    Ok(RelayPayload::Mint {
                        contract, chain_id, to, amount, beldex_txid, output_index, sig,
                    })
                }
                "rotate" => {
                    let new_signer = hex_fixed::<20>(get_str(&v, "new_signer")?, "new_signer")?;
                    let new_key_epoch = v
                        .get("new_key_epoch")
                        .and_then(Value::as_u64)
                        .ok_or(PayloadError::MissingField("new_key_epoch"))?;
                    let nonce = v
                        .get("nonce")
                        .and_then(Value::as_u64)
                        .ok_or(PayloadError::MissingField("nonce"))?;
                    // Accepted as a string so a deadline beyond 2^53 survives JSON.
                    let deadline = get_str(&v, "deadline")?
                        .parse::<u128>()
                        .map_err(|_| PayloadError::MissingField("deadline"))?;
                    Ok(RelayPayload::Rotate {
                        contract, chain_id, new_signer, new_key_epoch, nonce, deadline, sig,
                    })
                }
                "set_standby" => {
                    let standby = hex_fixed::<20>(get_str(&v, "standby")?, "standby")?;
                    let nonce = v.get("nonce").and_then(Value::as_u64).ok_or(PayloadError::MissingField("nonce"))?;
                    let deadline = get_str(&v, "deadline")?
                        .parse::<u128>()
                        .map_err(|_| PayloadError::MissingField("deadline"))?;
                    Ok(RelayPayload::SetStandby { contract, chain_id, standby, nonce, deadline, sig })
                }
                "activate" => {
                    let pending_signer = hex_fixed::<20>(get_str(&v, "pending_signer")?, "pending_signer")?;
                    let pending_key_epoch = v
                        .get("pending_key_epoch")
                        .and_then(Value::as_u64)
                        .ok_or(PayloadError::MissingField("pending_key_epoch"))?;
                    Ok(RelayPayload::Activate { contract, chain_id, pending_signer, pending_key_epoch, sig })
                }
                _ if step.is_some() => Ok(RelayPayload::TakeoverStep {
                    step: step.expect("checked"), contract, chain_id, sig,
                }),
                other => Err(PayloadError::UnknownKind(other.to_string())),
            }
        }

        /// Emit the payload as JSON (round-trips with [`from_json`](Self::from_json)).
        pub fn to_json(&self) -> String {
            let hexs = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            match self {
                RelayPayload::Mint {
                    contract, chain_id, to, amount, beldex_txid, output_index, sig,
                } => format!(
                    concat!(
                        r#"{{"kind":"mint","contract":"{}","chain_id":{},"to":"{}","#,
                        r#""amount":"{}","beldex_txid":"{}","output_index":{},"sig":"{}"}}"#
                    ),
                    hexs(contract), chain_id, hexs(to), amount, hexs(beldex_txid),
                    output_index, hexs(sig),
                ),
                RelayPayload::Rotate {
                    contract, chain_id, new_signer, new_key_epoch, nonce, deadline, sig,
                } => format!(
                    concat!(
                        r#"{{"kind":"rotate","contract":"{}","chain_id":{},"#,
                        r#""new_signer":"{}","new_key_epoch":{},"nonce":{},"#,
                        r#""deadline":"{}","sig":"{}"}}"#
                    ),
                    hexs(contract), chain_id, hexs(new_signer), new_key_epoch, nonce,
                    deadline, hexs(sig),
                ),
                RelayPayload::TakeoverStep { step, contract, chain_id, sig } => format!(
                    r#"{{"kind":"{}","contract":"{}","chain_id":{},"sig":"{}"}}"#,
                    step.json_kind(), hexs(contract), chain_id, hexs(sig),
                ),
                RelayPayload::SetStandby { contract, chain_id, standby, nonce, deadline, sig } => format!(
                    concat!(
                        r#"{{"kind":"set_standby","contract":"{}","chain_id":{},"standby":"{}","#,
                        r#""nonce":{},"deadline":"{}","sig":"{}"}}"#
                    ),
                    hexs(contract), chain_id, hexs(standby), nonce, deadline, hexs(sig),
                ),
                RelayPayload::Activate { contract, chain_id, pending_signer, pending_key_epoch, sig } => format!(
                    concat!(
                        r#"{{"kind":"activate","contract":"{}","chain_id":{},"#,
                        r#""pending_signer":"{}","pending_key_epoch":{},"sig":"{}"}}"#
                    ),
                    hexs(contract), chain_id, hexs(pending_signer), pending_key_epoch, hexs(sig),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mint() -> RelayPayload {
        RelayPayload::Mint {
            contract: [0x22; 20],
            chain_id: 1,
            to: [0x11; 20],
            amount: 1000,
            beldex_txid: [0xcd; 32], output_index: 0,
            sig: vec![0xab; 65],
        }
    }

    #[test]
    fn prepared_call_targets_the_contract_with_calldata() {
        let p = sample_mint();
        let call = p.to_prepared();
        assert_eq!(call.chain_id, 1);
        assert_eq!(call.to, [0x22; 20]);
        assert_eq!(&call.data[0..4], &crate::abi::MINT_SELECTOR);
        assert_eq!(call.data, p.calldata());
    }

    #[cfg(feature = "json")]
    #[cfg(feature = "json")]
    #[test]
    fn takeover_steps_round_trip_and_target_their_contract() {
        for (step, selector) in [
            (TakeoverStepKind::Begin, crate::abi::BEGIN_TAKEOVER_SELECTOR),
            (TakeoverStepKind::Complete, crate::abi::COMPLETE_TAKEOVER_SELECTOR),
            (TakeoverStepKind::Cancel, crate::abi::CANCEL_TAKEOVER_SELECTOR),
        ] {
            let p = RelayPayload::TakeoverStep { step, contract: [0x22; 20], chain_id: 31337, sig: vec![0xAB; 65] };
            let back = RelayPayload::from_json(&p.to_json()).unwrap();
            assert_eq!(back, p);
            let call = back.to_prepared();
            assert_eq!(call.chain_id, 31337);
            assert_eq!(call.to, [0x22; 20]);
            assert_eq!(&call.data[..4], &selector);
        }
        // The signer's cancel payload, exactly as it emits it.
        let cancel = r#"{"kind":"takeover_cancel","contract":"2222222222222222222222222222222222222222","chain_id":31337,"sig":"ab"}"#;
        assert!(matches!(
            RelayPayload::from_json(cancel).unwrap(),
            RelayPayload::TakeoverStep { step: TakeoverStepKind::Cancel, .. }
        ));
        assert!(matches!(
            RelayPayload::from_json(r#"{"kind":"takeover_cancel","chain_id":1,"contract":"22"}"#),
            Err(_)
        ));
    }

    #[cfg(feature = "json")]
    #[test]
    fn set_standby_round_trips_and_targets_its_contract() {
        let p = RelayPayload::SetStandby {
            contract: [0x22; 20],
            chain_id: 31337,
            standby: [0x33; 20],
            nonce: 5,
            deadline: 1_700_003_600,
            sig: vec![0xAB; 65],
        };
        assert_eq!(RelayPayload::from_json(&p.to_json()).unwrap(), p);
        let call = p.to_prepared();
        assert_eq!((call.chain_id, call.to), (31337, [0x22; 20]));
        assert_eq!(&call.data[..4], &crate::abi::SET_STANDBY_SELECTOR);
        assert!(RelayPayload::from_json(
            r#"{"kind":"set_standby","contract":"2222222222222222222222222222222222222222","chain_id":1,"sig":"ab"}"#
        )
        .is_err());
    }

    #[test]
    fn json_round_trips_mint_and_rotate() {
        let m = sample_mint();
        assert_eq!(RelayPayload::from_json(&m.to_json()).unwrap(), m);

        let r = RelayPayload::Rotate {
            contract: [0x22; 20],
            chain_id: 42,
            new_signer: [0x33; 20],
            new_key_epoch: 7,
            nonce: 3,
            // Past 2^53, so the round trip proves the deadline survives JSON.
            deadline: 9_007_199_254_740_995,
            sig: vec![0xee; 65],
        };
        assert_eq!(RelayPayload::from_json(&r.to_json()).unwrap(), r);

        let a = RelayPayload::Activate {
            contract: [0x22; 20],
            chain_id: 42,
            pending_signer: [0x33; 20],
            pending_key_epoch: 7,
            sig: vec![0xee; 65],
        };
        assert_eq!(RelayPayload::from_json(&a.to_json()).unwrap(), a);
        assert_eq!(&a.calldata()[0..4], &crate::abi::ACTIVATE_SELECTOR);
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_rejects_bad_fields() {
        assert!(matches!(
            RelayPayload::from_json(r#"{"kind":"nope","contract":"22","chain_id":1,"sig":"ab"}"#),
            Err(PayloadError::UnknownKind(_))
        ));
        assert_eq!(
            RelayPayload::from_json(r#"{"kind":"mint","chain_id":1}"#),
            Err(PayloadError::MissingField("contract"))
        );
        // A 19-byte contract is the wrong length.
        let bad = format!(
            r#"{{"kind":"mint","contract":"{}","chain_id":1,"to":"{}","amount":"1","beldex_txid":"{}","sig":"ab"}}"#,
            "11".repeat(19), "22".repeat(20), "cd".repeat(32)
        );
        assert_eq!(RelayPayload::from_json(&bad), Err(PayloadError::BadLength("contract")));

        // output_index is required and must fit u32: never defaulted, never truncated.
        let mint = |extra: &str| {
            format!(
                r#"{{"kind":"mint","contract":"{}","chain_id":1,"to":"{}","amount":"1","beldex_txid":"{}"{extra},"sig":"ab"}}"#,
                "11".repeat(20), "22".repeat(20), "cd".repeat(32)
            )
        };
        assert_eq!(RelayPayload::from_json(&mint("")), Err(PayloadError::MissingField("output_index")));
        assert_eq!(
            RelayPayload::from_json(&mint(r#","output_index":4294967297"#)),
            Err(PayloadError::OutOfRange("output_index"))
        );
        assert!(RelayPayload::from_json(&mint(r#","output_index":3"#)).is_ok());
    }
}

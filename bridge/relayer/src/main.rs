//! `beldex-bridge-relayer` — the reference courier + submit-your-own CLI (Phase I).
//!
//! ```text
//!   beldex-bridge-relayer prepare <payload.json | -->   # emit the ready-to-broadcast call
//! ```
//!
//! `prepare` reads a signed [`RelayPayload`] (a file path, or `-` for stdin) and prints the
//! exact `{chain_id, to, data}` to broadcast. Broadcast it yourself with any wallet, e.g.:
//!
//! ```text
//!   cast send <to> <data> --rpc-url <chain rpc> --private-key <your gas key>
//! ```
//!
//! This is the **liveness guarantee**: constructing this call needs no bridge key and no
//! running relayer service — the committee signature is already inside the payload.

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);

    match cmd {
        Some("prepare") => {
            let src = args.get(2).map(String::as_str).unwrap_or("-");
            match run_prepare(src) {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("prepare: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("mint-digest") => match run_mint_digest(&args[2..]) {
            Ok(out) => print!("{out}"),
            Err(e) => {
                eprintln!("mint-digest: {e}");
                std::process::exit(1);
            }
        },
        Some("relay") => {
            let src = args.get(2).map(String::as_str).unwrap_or("-");
            match run_relay(src) {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("relay: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!(
                "beldex-bridge-relayer {}\n\nusage:\n  \
                 beldex-bridge-relayer prepare <payload.json | ->\n  \
                 beldex-bridge-relayer relay   <payload.json | ->\n  \
                 beldex-bridge-relayer mint-digest --chain-id <n> --contract <20hex> --to <20hex> --amount <dec> --txid <32hex>\n\n\
                 `prepare`     reads a signed relay payload and prints the {{chain_id, to, data}} to broadcast.\n\
                 `relay`       signs + broadcasts it, paying gas (build with --features submit-http).\n\
                 `mint-digest` prints the 32-byte digest the Pevm committee signs for a mint\n\
                 (feed it to the signer as BRIDGE_SIGNER_SIGN_DIGEST).\n\n\
                 relay environment:\n  \
                 RELAYER_GAS_KEY_FILE owner-only file with the 32-byte hex secp256k1 gas key\n\
                 \t\t    (NOT a bridge key); or the systemd credential relayer-gas-key;\n\
                 \t\t    or, for test networks, RELAYER_GAS_KEY\n  \
                 RELAYER_CHAINS    JSON: [{{\"chain_id\":31337,\"rpc_url\":\"http://127.0.0.1:8545\"}}]\n\
                 \t\t    optional per chain: max_fee_cap_wei, priority_fee_wei, gas_limit_pct\n  \
                 RELAYER_STATE_DIR in-flight transactions per gas key (default relayer-state);\n\
                 \t\t    every relay on one gas key must share it",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(2);
        }
    }
}

/// `mint-digest --chain-id <n> --contract <20hex> --to <20hex> --amount <dec> --txid <32hex>`
/// → the 32-byte digest to feed the committee `sign` (`BRIDGE_SIGNER_SIGN_DIGEST`).
fn run_mint_digest(args: &[String]) -> Result<String, String> {
    let mut chain_id: Option<u64> = None;
    let mut contract: Option<[u8; 20]> = None;
    let mut to: Option<[u8; 20]> = None;
    let mut amount: Option<u128> = None;
    let mut txid: Option<[u8; 32]> = None;
    // Which gateway output of --txid this mint discharges. Optional: a single-output
    // deposit is 0, which is the overwhelming case, so operators need not pass it.
    let mut output_index: u32 = 0;

    let mut i = 0;
    while i + 1 < args.len() {
        let val = args[i + 1].as_str();
        match args[i].as_str() {
            "--chain-id" => chain_id = Some(val.parse().map_err(|_| "bad --chain-id".to_string())?),
            "--contract" => contract = Some(hex20(val, "--contract")?),
            "--to" => to = Some(hex20(val, "--to")?),
            "--amount" => amount = Some(val.parse().map_err(|_| "bad --amount".to_string())?),
            "--txid" => txid = Some(hex32(val, "--txid")?),
            "--output-index" => {
                output_index = val.parse().map_err(|_| "bad --output-index".to_string())?
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }

    let chain_id = chain_id.ok_or("missing --chain-id")?;
    let contract = contract.ok_or("missing --contract")?;
    let to = to.ok_or("missing --to")?;
    let amount = amount.ok_or("missing --amount")?;
    let txid = txid.ok_or("missing --txid")?;

    // The Pevm `sign` leg consumes the *preimage* (it keccaks it internally), so feed
    // `preimage` to BRIDGE_SIGNER_SIGN_PREIMAGE. `digest` = keccak256(preimage) is what the
    // contract recomputes and `ecrecover`s — shown for cross-checking.
    let preimage = beldex_bridge_relayer::mint_preimage(chain_id, contract, to, amount, txid, output_index);
    let digest = beldex_bridge_relayer::mint_digest(chain_id, contract, to, amount, txid, output_index);
    Ok(format!(
        "preimage: {}   # -> BRIDGE_SIGNER_SIGN_PREIMAGE (Pevm sign)\ndigest:   {}   # keccak256(preimage), the contract's ecrecover input\n",
        hex::encode(&preimage),
        hex::encode(digest),
    ))
}

fn hex20(s: &str, field: &str) -> Result<[u8; 20], String> {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("bad hex {field}"))?;
    b.try_into().map_err(|_| format!("{field} must be 20 bytes"))
}

fn hex32(s: &str, field: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("bad hex {field}"))?;
    b.try_into().map_err(|_| format!("{field} must be 32 bytes"))
}

#[cfg(feature = "json")]
fn run_prepare(src: &str) -> Result<String, String> {
    let json = read_source(src)?;
    let payload = beldex_bridge_relayer::RelayPayload::from_json(&json)
        .map_err(|e| format!("invalid payload: {e:?}"))?;
    let call = payload.to_prepared();
    Ok(format!(
        "chain_id: {}\nto:       0x{}\ndata:     0x{}\n",
        call.chain_id,
        hex::encode(call.to),
        hex::encode(&call.data),
    ))
}

#[cfg(not(feature = "json"))]
fn run_prepare(_src: &str) -> Result<String, String> {
    Err("built without the `json` feature; rebuild with --features json".into())
}

/// `relay <payload>` — sign the outer EIP-1559 envelope with the configured gas key and
/// broadcast. Reverts (already minted, over cap, bad signature) are caught by the gas
/// estimation dry-run and reported without spending anything.
///
/// The wallet's in-flight transactions are kept in `RELAYER_STATE_DIR` (default
/// `relayer-state`), so a payload already pending is not sent twice and a transaction stuck
/// below the base fee is re-priced by the next run. Every run on one gas key must share
/// that directory.
#[cfg(feature = "submit-http")]
fn run_relay(src: &str) -> Result<String, String> {
    use beldex_bridge_relayer::{HttpSubmitter, RelayOutcome, RelayPayload};

    let json = read_source(src)?;
    let payload =
        RelayPayload::from_json(&json).map_err(|e| format!("invalid payload: {e:?}"))?;

    let (key_hex, source) = beldex_bridge_relayer::gas_key::configured()?;
    if source == beldex_bridge_relayer::gas_key::Source::Environment {
        eprintln!(
            "WARNING: the gas key comes from RELAYER_GAS_KEY, which shows in process listings \
             and saved settings. Prefer RELAYER_GAS_KEY_FILE or the systemd credential `{}`.",
            beldex_bridge_relayer::gas_key::CREDENTIAL_NAME
        );
    }
    let key = hex32(&key_hex, "gas key")?;

    let chains_json = std::env::var("RELAYER_CHAINS")
        .map_err(|_| "set RELAYER_CHAINS (JSON array of {chain_id, rpc_url, …})".to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&chains_json).map_err(|e| format!("RELAYER_CHAINS: {e}"))?;
    let arr = v.as_array().ok_or("RELAYER_CHAINS must be a JSON array")?;
    let chains = parse_relayer_chains(arr)?;

    let state_dir = std::env::var("RELAYER_STATE_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "relayer-state".to_string());

    let submitter = HttpSubmitter::new(&key, chains).map_err(|e| format!("gas key: {e}"))?;
    // A hand-off whose key epoch is already live was completed — by this relayer, another, or
    // by hand — and can only revert now. Done, not failed, so a caller holding it stops.
    let target_epoch = match &payload {
        RelayPayload::Rotate { new_key_epoch, .. } => Some(*new_key_epoch),
        RelayPayload::Activate { pending_key_epoch, .. } => Some(*pending_key_epoch),
        RelayPayload::Mint { .. } | RelayPayload::TakeoverStep { .. } | RelayPayload::SetStandby { .. } => None,
    };
    if let Some(target) = target_epoch {
        let live = submitter
            .key_epoch(payload.chain_id(), &payload.contract())
            .map_err(|e| format!("read keyEpoch: {e:?}"))?;
        if live >= target {
            return Ok(format!(
                "already done: chain_id {} is at key epoch {live}, this hand-off was for {target}\n",
                payload.chain_id()
            ));
        }
    }
    let call = payload.to_prepared();
    let mut log = Vec::new();
    let result = submitter.relay(&call, &state_dir, &mut log);
    for line in &log {
        eprintln!("  {line}");
    }
    let (what, tx_hash, nonce) = match result.map_err(|e| format!("{e:?}"))? {
        RelayOutcome::Sent { tx_hash, nonce } => ("relayed", tx_hash, nonce),
        RelayOutcome::AlreadyPending { tx_hash, nonce } => ("already pending", tx_hash, nonce),
    };
    Ok(format!(
        "{what}: chain_id {} → {}\n  gas wallet: 0x{}\n  tx: {} (nonce {})\n",
        call.chain_id,
        format_args!("0x{}", hex::encode(call.to)),
        hex::encode(submitter.address),
        tx_hash,
        nonce,
    ))
}

#[cfg(not(feature = "submit-http"))]
fn run_relay(_src: &str) -> Result<String, String> {
    Err("built without the `submit-http` feature; rebuild with --features submit-http \
         (or use `prepare` + `cast send`, which needs no service)"
        .into())
}

fn read_source(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("stdin: {e}"))?;
        Ok(s)
    } else {
        std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))
    }
}

/// Every key a `RELAYER_CHAINS` entry may carry.
#[cfg(feature = "submit-http")]
const RELAYER_CHAIN_KEYS: &[&str] = &["chain_id", "rpc_url", "max_fee_cap_wei", "priority_fee_wei", "gas_limit_pct"];

/// Parse the `RELAYER_CHAINS` entries. Unknown keys are refused, and so is an optional fee
/// setting that is present but not a non-negative integer: either used to be ignored, so a
/// typo (`"max_fee_cap"`) or a quoted number left the default fee cap in force in silence.
#[cfg(feature = "submit-http")]
fn parse_relayer_chains(arr: &[serde_json::Value]) -> Result<Vec<beldex_bridge_relayer::ChainEndpoint>, String> {
    use beldex_bridge_relayer::ChainEndpoint;
    let mut chains = Vec::new();
    for (i, c) in arr.iter().enumerate() {
        let obj = c.as_object().ok_or_else(|| format!("RELAYER_CHAINS[{i}]: must be a JSON object"))?;
        if let Some(k) = obj.keys().find(|k| !RELAYER_CHAIN_KEYS.contains(&k.as_str())) {
            return Err(format!(
                "RELAYER_CHAINS[{i}]: unknown key `{k}` (known: {})",
                RELAYER_CHAIN_KEYS.join(", ")
            ));
        }
        let chain_id = c.get("chain_id").and_then(|x| x.as_u64()).ok_or("chain entry needs chain_id")?;
        let rpc_url = c.get("rpc_url").and_then(|x| x.as_str()).ok_or("chain entry needs rpc_url")?;
        let opt = |k: &str| -> Result<Option<u64>, String> {
            match c.get(k) {
                None => Ok(None),
                Some(v) => v
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| format!("RELAYER_CHAINS[{i}]: `{k}` must be a non-negative integer")),
            }
        };
        let mut ep = ChainEndpoint::new(chain_id, rpc_url);
        if let Some(x) = opt("max_fee_cap_wei")? {
            ep.max_fee_cap_wei = u128::from(x);
        }
        if let Some(x) = opt("priority_fee_wei")? {
            ep.priority_fee_wei = u128::from(x);
        }
        if let Some(x) = opt("gas_limit_pct")? {
            ep.gas_limit_pct = x;
        }
        chains.push(ep);
    }
    Ok(chains)
}

#[cfg(all(test, feature = "submit-http"))]
mod relayer_chain_config_tests {
    use super::parse_relayer_chains;

    fn parse(json: &str) -> Result<usize, String> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        parse_relayer_chains(v.as_array().unwrap()).map(|c| c.len())
    }

    #[test]
    fn unknown_keys_and_malformed_fee_settings_are_refused() {
        assert_eq!(parse(r#"[{"chain_id":1,"rpc_url":"x","max_fee_cap_wei":100}]"#), Ok(1));
        assert!(parse(r#"[{"chain_id":1,"rpc_url":"x","max_fee_cap":100}]"#).unwrap_err().contains("unknown key `max_fee_cap`"));
        assert!(parse(r#"[{"chain_id":1,"rpc_url":"x","max_fee_cap_wei":"100"}]"#).unwrap_err().contains("max_fee_cap_wei"));
        assert!(parse(r#"[{"chain_id":1,"rpc_url":"x","gas_limit_pct":-5}]"#).unwrap_err().contains("gas_limit_pct"));
        assert!(parse(r#"[{"chain_id":1}]"#).unwrap_err().contains("rpc_url"));
    }
}

//! Durable per-gas-wallet record of the transactions a relayer has in flight.
//!
//! `relay` used to be stateless: each run read the `pending` nonce, estimated, signed and
//! broadcast, then forgot. Three things went wrong with that once relaying ran unattended:
//!
//! * **Duplicate sends.** A payload delivered again while its first transaction was still
//!   pending (signers re-deliver unminted payloads; a relayer may watch several daemons)
//!   passed gas estimation again — the mint had not landed yet — and went out under the
//!   next nonce. One of the two then reverted on chain, paying gas for nothing.
//! * **A stuck transaction blocks every later one.** A transaction priced below a rising
//!   base fee sits in the mempool, and every later transaction from the same key queues
//!   behind its nonce. Nothing ever re-priced it, so one fee spike stalled all mints for
//!   that relayer until a person intervened.
//! * **Concurrent runs collide.** Two `relay` processes on one key read the same pending
//!   nonce, and one replaces or is refused in favour of the other.
//!
//! So each `(chain, gas wallet)` gets a state file, and every run holds an exclusive lock on
//! it while it decides. A transaction is recorded before it is broadcast. A later run that
//! finds it still unmined after [`REPLACE_AFTER_SECS`] re-signs it at the same nonce with
//! higher fees; one whose call would now revert (the deposit was minted by someone else) is
//! replaced by a zero-value transfer to itself, which frees the nonce without paying for a
//! revert. A payload whose call is already in flight is not sent again.
//!
//! The decisions are pure functions over [`RelayState`], so they are tested without a chain.

use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// How long a transaction may stay unmined before it is re-priced. A few blocks on any
/// chain the bridge targets; short enough that one fee spike does not stall a queue for
/// long, long enough not to churn replacements for a transaction about to be included.
pub const REPLACE_AFTER_SECS: u64 = 3 * 60;

/// A replacement must outbid the transaction it replaces. Nodes require at least +10% on
/// both the fee cap and the tip; +25% clears that with margin and catches up with a rising
/// base fee in a few steps.
pub const BUMP_PCT: u128 = 125;

/// One transaction this wallet signed and has not yet seen mined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub nonce: u64,
    /// `0x`-hex hash of the latest signed version at this nonce.
    pub tx_hash: String,
    /// The call it carries; empty `data` to this wallet itself when `cancel` is set.
    pub to: [u8; 20],
    pub data: Vec<u8>,
    pub max_fee: u128,
    pub tip: u128,
    pub gas_limit: u64,
    /// Unix seconds of the latest broadcast at this nonce.
    pub sent_at: u64,
    /// Replaced by a zero-value self-transfer because its call no longer succeeds.
    pub cancel: bool,
}

impl InFlight {
    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.sent_at) >= REPLACE_AFTER_SECS
    }

    /// Whether this entry carries exactly `to`/`data` (and was not cancelled).
    pub fn carries(&self, to: &[u8; 20], data: &[u8]) -> bool {
        !self.cancel && &self.to == to && self.data == data
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayState {
    pub in_flight: Vec<InFlight>,
}

impl RelayState {
    /// Forget every transaction below the account's mined nonce: something at each of those
    /// nonces was included — ours, or a replacement of ours — so none can still be pending.
    pub fn prune_mined(&mut self, mined_nonce: u64) {
        self.in_flight.retain(|e| e.nonce >= mined_nonce);
    }

    /// The pending entry already carrying this call, if any.
    pub fn find_call(&self, to: &[u8; 20], data: &[u8]) -> Option<&InFlight> {
        self.in_flight.iter().find(|e| e.carries(to, data))
    }

    /// The nonce for a new transaction. The node's pending count can fall behind what this
    /// wallet has signed — a node that dropped one of ours from its mempool no longer counts
    /// it — and reusing such a nonce would collide with our own recorded transaction. That
    /// one is re-broadcast when it goes stale, which fills the gap.
    pub fn next_nonce(&self, pending_nonce: u64) -> u64 {
        let after_ours = self.in_flight.iter().map(|e| e.nonce + 1).max().unwrap_or(0);
        pending_nonce.max(after_ours)
    }

    /// Entries due for re-pricing, lowest nonce first: the lowest one is what blocks the rest.
    pub fn stale(&self, now: u64) -> Vec<InFlight> {
        let mut v: Vec<InFlight> = self.in_flight.iter().filter(|e| e.is_stale(now)).cloned().collect();
        v.sort_by_key(|e| e.nonce);
        v
    }

    /// Insert or replace the entry at `e.nonce`.
    pub fn record(&mut self, e: InFlight) {
        self.in_flight.retain(|x| x.nonce != e.nonce);
        self.in_flight.push(e);
        self.in_flight.sort_by_key(|x| x.nonce);
    }

    pub fn remove(&mut self, nonce: u64) {
        self.in_flight.retain(|x| x.nonce != nonce);
    }

    pub fn to_json(&self) -> String {
        let entries: Vec<Value> = self
            .in_flight
            .iter()
            .map(|e| {
                json!({
                    "nonce": e.nonce,
                    "tx_hash": e.tx_hash,
                    "to": hex::encode(e.to),
                    "data": hex::encode(&e.data),
                    "max_fee": e.max_fee.to_string(),
                    "tip": e.tip.to_string(),
                    "gas_limit": e.gas_limit,
                    "sent_at": e.sent_at,
                    "cancel": e.cancel,
                })
            })
            .collect();
        json!({ "in_flight": entries }).to_string()
    }

    /// Strict: a state file this cannot read is an error, not an empty state. Treating it
    /// as empty would reuse nonces this wallet has already signed for.
    pub fn from_json(s: &str) -> Result<RelayState, String> {
        let v: Value = serde_json::from_str(s).map_err(|e| format!("relay state: {e}"))?;
        let arr = v
            .get("in_flight")
            .and_then(Value::as_array)
            .ok_or("relay state: missing in_flight")?;
        let mut in_flight = Vec::with_capacity(arr.len());
        for e in arr {
            let u = |k: &str| e.get(k).and_then(Value::as_u64).ok_or(format!("relay state: bad {k}"));
            let big = |k: &str| -> Result<u128, String> {
                e.get(k)
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse().ok())
                    .ok_or(format!("relay state: bad {k}"))
            };
            let s = |k: &str| e.get(k).and_then(Value::as_str).ok_or(format!("relay state: bad {k}"));
            let to: [u8; 20] = hex::decode(s("to")?)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or("relay state: bad to")?;
            in_flight.push(InFlight {
                nonce: u("nonce")?,
                tx_hash: s("tx_hash")?.to_string(),
                to,
                data: hex::decode(s("data")?).map_err(|_| "relay state: bad data")?,
                max_fee: big("max_fee")?,
                tip: big("tip")?,
                gas_limit: u("gas_limit")?,
                sent_at: u("sent_at")?,
                cancel: e.get("cancel").and_then(Value::as_bool).unwrap_or(false),
            });
        }
        in_flight.sort_by_key(|x| x.nonce);
        Ok(RelayState { in_flight })
    }
}

/// Fees for a replacement: at least [`BUMP_PCT`] of what the previous version offered, and at
/// least what the chain asks for now.
pub fn bumped_fees(old_max: u128, old_tip: u128, now_max: u128, now_tip: u128) -> (u128, u128) {
    let bump = |x: u128| x.saturating_mul(BUMP_PCT) / 100 + 1;
    let tip = bump(old_tip).max(now_tip);
    let max = bump(old_max).max(now_max).max(tip);
    (max, tip)
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An open, exclusively locked state file for one `(chain, gas wallet)`. The lock is held
/// until this is dropped, so concurrent `relay` runs on one wallet take turns.
pub struct StateFile {
    path: PathBuf,
    _lock: File,
}

impl StateFile {
    pub fn open(dir: &str, chain_id: u64, wallet: &[u8; 20]) -> Result<(StateFile, RelayState), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {dir}: {e}"))?;
        let base = Path::new(dir).join(format!("{chain_id}-0x{}", hex::encode(wallet)));
        let lock_path = base.with_extension("lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("open {lock_path:?}: {e}"))?;
        lock.lock().map_err(|e| format!("lock {lock_path:?}: {e}"))?;
        let path = base.with_extension("json");
        let state = match File::open(&path) {
            Ok(mut f) => {
                let mut s = String::new();
                f.read_to_string(&mut s).map_err(|e| format!("read {path:?}: {e}"))?;
                RelayState::from_json(&s)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RelayState::default(),
            Err(e) => return Err(format!("open {path:?}: {e}")),
        };
        Ok((StateFile { path, _lock: lock }, state))
    }

    /// Atomic and durable: written to a scratch file, fsynced, renamed over the old one,
    /// and the directory fsynced, so a crash leaves the old state or the new, never half.
    pub fn save(&self, state: &RelayState) -> Result<(), String> {
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = File::create(&tmp).map_err(|e| format!("create {tmp:?}: {e}"))?;
            f.write_all(state.to_json().as_bytes()).map_err(|e| format!("write: {e}"))?;
            f.sync_all().map_err(|e| format!("fsync: {e}"))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("rename: {e}"))?;
        if let Some(dir) = self.path.parent() {
            File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("fsync dir: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(nonce: u64, sent_at: u64, data: &[u8]) -> InFlight {
        InFlight {
            nonce,
            tx_hash: format!("0x{nonce:064x}"),
            to: [0x22; 20],
            data: data.to_vec(),
            max_fee: 100,
            tip: 10,
            gas_limit: 90_000,
            sent_at,
            cancel: false,
        }
    }

    #[test]
    fn mined_nonces_are_forgotten() {
        let mut s = RelayState::default();
        for n in [3, 4, 5] {
            s.record(entry(n, 0, &[n as u8]));
        }
        s.prune_mined(5);
        assert_eq!(s.in_flight.iter().map(|e| e.nonce).collect::<Vec<_>>(), vec![5]);
    }

    /// The duplicate-send case: the same call delivered again while still pending is found,
    /// so it is not signed under a second nonce.
    #[test]
    fn a_call_already_in_flight_is_found() {
        let mut s = RelayState::default();
        s.record(entry(7, 0, b"mint-a"));
        assert!(s.find_call(&[0x22; 20], b"mint-a").is_some());
        assert!(s.find_call(&[0x22; 20], b"mint-b").is_none());
        assert!(s.find_call(&[0x33; 20], b"mint-a").is_none(), "another contract");

        // A cancelled entry no longer carries its call: the call may need sending afresh.
        let mut c = entry(8, 0, b"mint-c");
        c.cancel = true;
        s.record(c);
        assert!(s.find_call(&[0x22; 20], b"mint-c").is_none());
    }

    /// A node that dropped our transaction reports a lower pending nonce. A new transaction
    /// must not take the nonce we already signed for.
    #[test]
    fn next_nonce_never_reuses_one_we_signed() {
        let mut s = RelayState::default();
        assert_eq!(s.next_nonce(4), 4, "nothing of ours in flight: the node decides");
        s.record(entry(4, 0, b"a"));
        s.record(entry(5, 0, b"b"));
        assert_eq!(s.next_nonce(4), 6, "the node forgot 4 and 5; we did not");
        assert_eq!(s.next_nonce(9), 9, "the node knows of later ones (another tool)");
    }

    #[test]
    fn stale_entries_come_lowest_nonce_first() {
        let mut s = RelayState::default();
        s.record(entry(9, 0, b"x"));
        s.record(entry(7, 0, b"y"));
        s.record(entry(8, 1_000, b"z"));
        let now = REPLACE_AFTER_SECS;
        let got: Vec<u64> = s.stale(now).iter().map(|e| e.nonce).collect();
        assert_eq!(got, vec![7, 9], "8 was sent recently; 7 blocks the rest");
    }

    #[test]
    fn a_replacement_outbids_by_enough_and_tracks_the_chain() {
        let (max, tip) = bumped_fees(100, 10, 0, 0);
        assert!(max * 100 >= 100 * 110 && tip * 100 >= 10 * 110, "nodes need at least +10%");
        // If the chain now asks for more than the bump, pay what the chain asks.
        let (max, tip) = bumped_fees(100, 10, 1_000, 50);
        assert_eq!((max, tip), (1_000, 50));
        // The fee cap never falls below the tip.
        let (max, tip) = bumped_fees(10, 100, 0, 0);
        assert!(max >= tip);
    }

    #[test]
    fn state_round_trips_and_a_damaged_file_is_an_error() {
        let mut s = RelayState::default();
        let mut e = entry(1, 42, &[1, 2, 3]);
        e.max_fee = u128::MAX; // larger than any JSON number: kept as a string
        e.cancel = true;
        s.record(e);
        s.record(entry(2, 43, &[]));
        assert_eq!(RelayState::from_json(&s.to_json()).unwrap(), s);
        assert!(RelayState::from_json("{").is_err());
        assert!(RelayState::from_json(r#"{"in_flight":[{"nonce":1}]}"#).is_err());
    }

    #[test]
    fn the_state_file_persists_and_serializes_runs() {
        let dir = std::env::temp_dir().join(format!("bx-relay-state-{}", std::process::id()));
        let dir = dir.to_str().unwrap().to_string();
        let wallet = [0xab; 20];
        {
            let (f, mut s) = StateFile::open(&dir, 31337, &wallet).unwrap();
            assert!(s.in_flight.is_empty());
            s.record(entry(3, 9, b"m"));
            f.save(&s).unwrap();

            // While this run holds the lock, another cannot take it.
            let lock = Path::new(&dir).join(format!("31337-0x{}.lock", hex::encode(wallet)));
            let other = OpenOptions::new().write(true).open(lock).unwrap();
            assert!(other.try_lock().is_err(), "a second run must wait its turn");
        }
        let (_f, s) = StateFile::open(&dir, 31337, &wallet).unwrap();
        assert_eq!(s.in_flight.len(), 1);
        assert_eq!(s.in_flight[0].nonce, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

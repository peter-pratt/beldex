//! Durable record of a signed BDX release, so it survives to be re-sent.
//!
//! A release was previously discarded the moment the daemon accepted it — but acceptance
//! into the mempool is not inclusion in a block. If the transaction is later dropped (a
//! fee spike evicting it is enough) nothing re-sent it, the watcher had already moved past
//! the burn, and the user's wBDX was destroyed with no BDX ever arriving. No attacker is
//! involved; a busy network suffices.
//!
//! Two rules make re-sending safe:
//!
//! * **Re-broadcast, never re-sign.** The same signed bytes carry the same transaction id,
//!   so the chain simply ignores a duplicate. Paying twice is impossible by construction.
//!   Signing a *fresh* transaction for the same burn is what would create that risk.
//! * **Stop well inside the chain's memory.** Consensus refuses a second discharge of a
//!   burn for `GATEWAY_RELEASE_WINDOW_BLOCKS` (24h at 30s blocks, current + previous
//!   window). Past that it forgets, and a stale re-send would have nothing stopping it.
//!   Automatic retries therefore stop at half that.
//!
//! The record keeps the transaction id precisely so a person recovering by hand can ask
//! one question — "is this id on chain?" — and get a complete answer. Because we never
//! re-sign, that id is the *only* transaction that can ever pay this burn.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Interval between automatic re-sends. A Beldex block is ~30s, so this is ~30 blocks —
/// long enough for inclusion, rather than re-sending before a block can even exist.
pub const RETRY_INTERVAL_SECS: u64 = 15 * 60;

/// How long to keep re-sending before giving up and asking for a person.
///
/// Half the 24h window consensus is guaranteed to remember the burn for. Beyond that a
/// re-send could land after the chain has forgotten, and pay twice. It is also well past
/// the point where the cause is a fee: a release that cannot be mined in twelve hours has
/// something structurally wrong that more attempts will not fix.
pub const GIVE_UP_AFTER_SECS: u64 = 12 * 60 * 60;

/// One signed release, kept until it is known to have landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRecord {
    /// The transaction id of the signed bytes. The single thing to check on chain.
    pub txid: String,
    pub tx_blob: String,
    pub signature: String,
    /// The burn this discharges, so a human can tie it back to a user's withdrawal.
    pub chain_id: u64,
    pub evm_txid: String,
    pub log_index: u32,
    /// Unix seconds when it was first signed — the clock the retry window runs on.
    pub first_seen: u64,
    pub attempts: u32,
    /// Set once retries stop, so a sweep can tell "still trying" from "needs a person".
    pub gave_up: bool,
}

impl ReleaseRecord {
    /// Seconds since this release was first signed.
    pub fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.first_seen)
    }

    /// Whether automatic re-sending should stop and ask for a person instead.
    pub fn should_give_up(&self, now: u64) -> bool {
        self.age_secs(now) >= GIVE_UP_AFTER_SECS
    }

    /// Whether enough time has passed since the last attempt to try again.
    pub fn due(&self, now: u64, last_attempt: u64) -> bool {
        !self.should_give_up(now) && now.saturating_sub(last_attempt) >= RETRY_INTERVAL_SECS
    }

    pub fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"txid":"{}","tx_blob":"{}","signature":"{}","chain_id":{},"#,
                r#""evm_txid":"{}","log_index":{},"first_seen":{},"attempts":{},"#,
                r#""gave_up":{}}}"#
            ),
            self.txid,
            self.tx_blob,
            self.signature,
            self.chain_id,
            self.evm_txid,
            self.log_index,
            self.first_seen,
            self.attempts,
            self.gave_up,
        )
    }

    pub fn from_json(s: &str) -> Option<ReleaseRecord> {
        let str_field = |k: &str| -> Option<String> {
            let pat = format!("\"{k}\":\"");
            let i = s.find(&pat)? + pat.len();
            let rest = &s[i..];
            Some(rest[..rest.find('"')?].to_string())
        };
        let num_field = |k: &str| -> Option<u64> {
            let pat = format!("\"{k}\":");
            let i = s.find(&pat)? + pat.len();
            let rest = &s[i..];
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse().ok()
        };
        Some(ReleaseRecord {
            txid: str_field("txid")?,
            tx_blob: str_field("tx_blob")?,
            signature: str_field("signature")?,
            chain_id: num_field("chain_id")?,
            evm_txid: str_field("evm_txid")?,
            log_index: num_field("log_index")? as u32,
            first_seen: num_field("first_seen")?,
            attempts: num_field("attempts")? as u32,
            gave_up: s.contains("\"gave_up\":true"),
        })
    }
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One record per burn — `(chain, evm_txid, log_index)` names it uniquely, and is the same
/// key consensus dedupes releases on.
fn path_for(dir: &str, chain_id: u64, evm_txid: &str, log_index: u32) -> PathBuf {
    Path::new(dir).join(format!("{chain_id}-{evm_txid}-{log_index}.json"))
}

/// Write the record, atomically. A crash mid-write must not leave a half-parsed record
/// standing between a user and their funds.
pub fn save(dir: &str, rec: &ReleaseRecord) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {dir}: {e}"))?;
    let path = path_for(dir, rec.chain_id, &rec.evm_txid, rec.log_index);
    // The scratch name must be unique per WRITE, not derived from the record. Every
    // finalizing member signs the SAME release, and members can share one outbox
    // directory; with a shared scratch name they each truncate the previous writer's
    // file and all but one rename fails with ENOENT. That looked like a missing
    // directory and made the losers refuse to submit a release they had already signed.
    // The pid separates members, the counter separates writes inside one member.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}-{seq}.tmp", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create {tmp:?}: {e}"))?;
        f.write_all(rec.to_json().as_bytes()).map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;
    Ok(path)
}

/// Forget a release that is known to have landed.
pub fn remove(dir: &str, rec: &ReleaseRecord) {
    let _ = std::fs::remove_file(path_for(dir, rec.chain_id, &rec.evm_txid, rec.log_index));
}

/// Every release still outstanding, oldest first.
pub fn load_all(dir: &str) -> Vec<(PathBuf, ReleaseRecord)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, ReleaseRecord)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            ReleaseRecord::from_json(&text).map(|r| (p, r))
        })
        .collect();
    out.sort_by_key(|(_, r)| r.first_seen);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(first_seen: u64) -> ReleaseRecord {
        ReleaseRecord {
            txid: "deadbeef".into(),
            tx_blob: "0011".into(),
            signature: "aabb".into(),
            chain_id: 56,
            evm_txid: "abc123".into(),
            log_index: 2,
            first_seen,
            attempts: 0,
            gave_up: false,
        }
    }

    fn tmpdir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("bx-outbox-{tag}-{}", std::process::id()));
        d.to_str().unwrap().to_string()
    }

    /// The record has to survive a restart intact — it is the only thing standing between
    /// a dropped payout and a user who never gets paid.
    #[test]
    fn a_saved_release_reloads_exactly() {
        let dir = tmpdir("roundtrip");
        let r = rec(1_700_000_000);
        save(&dir, &r).unwrap();

        let loaded = load_all(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, r, "every field must survive, especially the txid");

        remove(&dir, &r);
        assert!(load_all(&dir).is_empty(), "a landed release is forgotten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Re-sending is paced: a Beldex block is ~30s, so re-sending every tick would repeat
    /// before a block could exist.
    #[test]
    fn a_resend_is_due_only_after_the_interval() {
        let r = rec(1000);
        let now = 1000 + RETRY_INTERVAL_SECS;
        assert!(!r.due(now, now - 60), "one minute since the last try is too soon");
        assert!(r.due(now, now - RETRY_INTERVAL_SECS), "a full interval has passed");
    }

    /// Retrying must stop well inside the window consensus remembers the burn for. Past
    /// that, a stale re-send could land after the chain has forgotten and pay twice.
    #[test]
    fn retrying_stops_at_half_the_window_the_chain_remembers() {
        let r = rec(1000);
        assert!(!r.should_give_up(1000 + GIVE_UP_AFTER_SECS - 1), "still inside the window");
        assert!(r.should_give_up(1000 + GIVE_UP_AFTER_SECS), "stop and ask for a person");

        // And once it gives up, nothing is due any more — no quiet background retrying.
        let now = 1000 + GIVE_UP_AFTER_SECS;
        assert!(!r.due(now, 0), "a given-up release must not keep re-sending");

        // The bound that makes this safe: consensus remembers for 24h, we stop at 12h.
        assert!(
            GIVE_UP_AFTER_SECS * 2 <= 24 * 60 * 60,
            "give-up must stay well inside the chain's 24h replay window"
        );
    }

    /// 15-minute pacing over 12 hours is 48 attempts — few enough to reason about, and
    /// each is a re-send of the same bytes rather than a fresh signing round.
    #[test]
    fn the_retry_budget_is_forty_eight_attempts() {
        assert_eq!(GIVE_UP_AFTER_SECS / RETRY_INTERVAL_SECS, 48);
    }

    /// One record per burn: re-saving must update in place, never accumulate copies that
    /// a sweep would treat as separate unpaid withdrawals.
    #[test]
    fn re_saving_the_same_burn_updates_in_place() {
        let dir = tmpdir("inplace");
        let mut r = rec(1000);
        save(&dir, &r).unwrap();
        r.attempts = 7;
        r.gave_up = true;
        save(&dir, &r).unwrap();

        let loaded = load_all(&dir);
        assert_eq!(loaded.len(), 1, "one burn, one record");
        assert_eq!(loaded[0].1.attempts, 7);
        assert!(loaded[0].1.gave_up, "the given-up flag survives, so a sweep can see it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Oldest first, so a sweep deals with the longest-waiting user first.
    #[test]
    fn outstanding_releases_come_back_oldest_first() {
        let dir = tmpdir("order");
        for (i, t) in [(1u32, 3000u64), (2, 1000), (3, 2000)] {
            let mut r = rec(t);
            r.log_index = i;
            save(&dir, &r).unwrap();
        }
        let got: Vec<u64> = load_all(&dir).iter().map(|(_, r)| r.first_seen).collect();
        assert_eq!(got, vec![1000, 2000, 3000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every finalizing member signs the SAME release, and members may share one outbox
    /// directory. Concurrent saves of one record must all succeed: a writer whose save
    /// fails refuses to submit a release it has already signed, so a scratch-file
    /// collision here silently costs the payout its fastest submitter.
    #[test]
    fn concurrent_saves_of_one_release_all_succeed() {
        let dir = tmpdir("concurrent");
        let errs: Vec<String> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    let d = dir.clone();
                    sc.spawn(move || {
                        let mut bad = Vec::new();
                        for _ in 0..25 {
                            if let Err(e) = save(&d, &rec(1000)) {
                                bad.push(e);
                            }
                        }
                        bad
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        assert!(errs.is_empty(), "concurrent saves failed: {errs:?}");
        assert_eq!(load_all(&dir).len(), 1, "one burn is still one record");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

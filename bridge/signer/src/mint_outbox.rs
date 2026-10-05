//! Durable record of a signed mint payload, kept until the mint is seen on chain.
//!
//! The committee's work on a deposit ends with a signature; someone else's transaction
//! turns it into wBDX. The hand-off to that someone — the daemon's mint bus and an
//! optional relay command — is fire-and-forget. A relayer that is down, a bus daemon that
//! restarts, or a relay that fails once was enough to strand the deposit: the duty was
//! already done, the watcher had moved past the deposit, and the only copy of the payload
//! was a `MINT-PAYLOAD` line in a log. The user's BDX sat locked in the gateway until a
//! person found that line.
//!
//! So the payload is saved before it is handed off, and handed off again until the
//! contract's `processedDeposits` says it landed.
//!
//! Re-delivering a mint can never pay twice: the contract refuses a deposit it has already
//! minted, permanently (unlike the native side, whose release replay guard forgets after a
//! window). So retries need no safety cut-off. They do stop eventually, because a payload
//! signed by a key that has since been rotated out can never mint, and retrying it forever
//! would only hide that a person has to re-sign it.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Interval between re-deliveries. Long enough for a relayer to have mined the previous
/// one, and longer than the daemon's re-fan quiet period so each re-delivery reaches
/// subscribers again rather than being collapsed into the last one.
pub const RETRY_INTERVAL_SECS: u64 = 5 * 60;

/// After this long unminted, warn once that something structural is wrong — a relayer
/// with no gas, a paused contract, a rotated-out key — while still retrying.
pub const STALE_AFTER_SECS: u64 = 60 * 60;

/// After this long, stop retrying and ask for a person. Re-delivery is safe for ever, but
/// a payload that has not minted in a week will not mint by being sent again.
pub const GIVE_UP_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// One signed mint, kept until it is known to have landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRecord {
    /// Destination EVM chain and the deposit, as the contract keys its replay guard.
    pub chain_id: u64,
    /// Hex, no `0x`.
    pub beldex_txid: String,
    pub output_index: u32,
    /// The relay payload JSON exactly as first handed off — what a relayer needs to mint.
    pub payload: String,
    /// Unix seconds when it was first signed.
    pub first_seen: u64,
    /// Unix seconds of the latest delivery. Re-delivery waits a full interval from here,
    /// not from a sweep tick, so a payload handed off just before a sweep is not sent
    /// again while a relayer's transaction for it may still be pending.
    pub last_attempt: u64,
    pub attempts: u32,
    /// Set once the stale warning has been printed, so it is printed once.
    pub warned: bool,
    /// Set once retries stop, so a sweep can tell "still trying" from "needs a person".
    pub gave_up: bool,
}

impl MintRecord {
    pub fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.first_seen)
    }

    pub fn is_stale(&self, now: u64) -> bool {
        self.age_secs(now) >= STALE_AFTER_SECS
    }

    pub fn should_give_up(&self, now: u64) -> bool {
        self.age_secs(now) >= GIVE_UP_AFTER_SECS
    }

    /// Whether a full interval has passed since the latest delivery.
    pub fn due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_attempt) >= RETRY_INTERVAL_SECS
    }

    /// The payload is stored hex-encoded: it is JSON itself, and this record is parsed
    /// without a JSON library so the module stays std-only like the release outbox.
    pub fn to_json(&self) -> String {
        let payload_hex: String = self.payload.bytes().map(|b| format!("{b:02x}")).collect();
        format!(
            concat!(
                r#"{{"chain_id":{},"beldex_txid":"{}","output_index":{},"payload_hex":"{}","#,
                r#""first_seen":{},"last_attempt":{},"attempts":{},"warned":{},"gave_up":{}}}"#
            ),
            self.chain_id,
            self.beldex_txid,
            self.output_index,
            payload_hex,
            self.first_seen,
            self.last_attempt,
            self.attempts,
            self.warned,
            self.gave_up,
        )
    }

    pub fn from_json(s: &str) -> Option<MintRecord> {
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
        let payload_hex = str_field("payload_hex")?;
        if payload_hex.len() % 2 != 0 {
            return None;
        }
        let bytes: Option<Vec<u8>> = (0..payload_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&payload_hex[i..i + 2], 16).ok())
            .collect();
        Some(MintRecord {
            chain_id: num_field("chain_id")?,
            beldex_txid: str_field("beldex_txid")?,
            output_index: u32::try_from(num_field("output_index")?).ok()?,
            payload: String::from_utf8(bytes?).ok()?,
            first_seen: num_field("first_seen")?,
            last_attempt: num_field("last_attempt")?,
            attempts: u32::try_from(num_field("attempts")?).ok()?,
            warned: s.contains("\"warned\":true"),
            gave_up: s.contains("\"gave_up\":true"),
        })
    }
}

/// One record per deposit output: `(chain, beldex_txid, output_index)` is the key the
/// contract dedupes mints on.
fn path_for(dir: &str, chain_id: u64, beldex_txid: &str, output_index: u32) -> PathBuf {
    Path::new(dir).join(format!("{chain_id}-{beldex_txid}-{output_index}.json"))
}

/// Write the record atomically and durably: the file is fsynced before the rename and the
/// directory after it, so a crash can neither leave half a record nor lose the rename.
pub fn save(dir: &str, rec: &MintRecord) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {dir}: {e}"))?;
    let path = path_for(dir, rec.chain_id, &rec.beldex_txid, rec.output_index);
    // Unique per write, not per record: members may share a directory and save the same
    // deposit at once (see release_outbox::save).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}-{seq}.tmp", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create {tmp:?}: {e}"))?;
        f.write_all(rec.to_json().as_bytes()).map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {dir}: {e}"))?;
    Ok(path)
}

/// Forget a mint that is known to have landed.
pub fn remove(dir: &str, rec: &MintRecord) {
    let _ = std::fs::remove_file(path_for(dir, rec.chain_id, &rec.beldex_txid, rec.output_index));
}

/// Every mint still outstanding, oldest first.
pub fn load_all(dir: &str) -> Vec<(PathBuf, MintRecord)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, MintRecord)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            MintRecord::from_json(&text).map(|r| (p, r))
        })
        .collect();
    out.sort_by_key(|(_, r)| r.first_seen);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str = r#"{"kind":"mint","contract":"aa","chain_id":56,"to":"bb","amount":"5","beldex_txid":"abc123","output_index":1,"sig":"cc"}"#;

    fn rec(first_seen: u64) -> MintRecord {
        MintRecord {
            chain_id: 56,
            beldex_txid: "abc123".into(),
            output_index: 1,
            payload: PAYLOAD.into(),
            first_seen,
            last_attempt: first_seen,
            attempts: 1,
            warned: false,
            gave_up: false,
        }
    }

    fn tmpdir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("bx-mint-outbox-{tag}-{}", std::process::id()));
        d.to_str().unwrap().to_string()
    }

    /// The payload must come back byte for byte: a relayer rebuilds the mint call from it,
    /// and the signature only verifies over the exact fields.
    #[test]
    fn a_saved_mint_reloads_exactly() {
        let dir = tmpdir("roundtrip");
        let r = rec(1_700_000_000);
        save(&dir, &r).unwrap();
        let loaded = load_all(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, r);
        assert_eq!(loaded[0].1.payload, PAYLOAD);
        remove(&dir, &r);
        assert!(load_all(&dir).is_empty(), "a minted deposit is forgotten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One Beldex transaction can pay several gateway outputs, each its own mint. They
    /// must be separate records, or saving the second would overwrite the first.
    #[test]
    fn each_output_of_one_transaction_is_its_own_record() {
        let dir = tmpdir("outputs");
        let a = rec(1000);
        let mut b = rec(1000);
        b.output_index = 2;
        save(&dir, &a).unwrap();
        save(&dir, &b).unwrap();
        let idx: Vec<u32> = load_all(&dir).iter().map(|(_, r)| r.output_index).collect();
        assert_eq!(idx.len(), 2);
        assert!(idx.contains(&1) && idx.contains(&2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_saving_the_same_deposit_updates_in_place() {
        let dir = tmpdir("inplace");
        let mut r = rec(1000);
        save(&dir, &r).unwrap();
        r.attempts = 9;
        r.warned = true;
        save(&dir, &r).unwrap();
        let loaded = load_all(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.attempts, 9);
        assert!(loaded[0].1.warned);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pacing runs from the latest delivery: a payload handed off a moment ago is not due,
    /// however the sweep's own ticks happen to fall.
    #[test]
    fn re_delivery_waits_a_full_interval_after_the_last() {
        let mut r = rec(1000);
        r.last_attempt = 5000;
        assert!(!r.due(5000 + RETRY_INTERVAL_SECS - 1));
        assert!(r.due(5000 + RETRY_INTERVAL_SECS));
    }

    #[test]
    fn warning_comes_before_giving_up() {
        let r = rec(1000);
        assert!(!r.is_stale(1000 + STALE_AFTER_SECS - 1));
        assert!(r.is_stale(1000 + STALE_AFTER_SECS));
        assert!(!r.should_give_up(1000 + STALE_AFTER_SECS));
        assert!(r.should_give_up(1000 + GIVE_UP_AFTER_SECS));
        assert!(STALE_AFTER_SECS < GIVE_UP_AFTER_SECS);
    }

    /// A damaged record is skipped, not misread: half a payload would sign nothing useful.
    #[test]
    fn a_damaged_record_is_skipped() {
        let good = rec(1000).to_json();
        assert!(MintRecord::from_json(&good).is_some());
        let odd = good.replace("\"payload_hex\":\"", "\"payload_hex\":\"0");
        assert!(MintRecord::from_json(&odd).is_none(), "odd-length hex");
        let bad = good.replace("\"payload_hex\":\"", "\"payload_hex\":\"zz");
        assert!(MintRecord::from_json(&bad).is_none(), "non-hex payload");
    }

    #[test]
    fn concurrent_saves_of_one_mint_all_succeed() {
        let dir = tmpdir("concurrent");
        let errs: Vec<String> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    let d = dir.clone();
                    sc.spawn(move || {
                        (0..25).filter_map(|_| save(&d, &rec(1000)).err()).collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        assert!(errs.is_empty(), "concurrent saves failed: {errs:?}");
        assert_eq!(load_all(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

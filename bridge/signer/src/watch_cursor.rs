//! Durable watcher cursors: how far each chain has been fully handled, so a restarted
//! signer resumes there instead of rescanning from its configured start (H-04).
//!
//! A restart used to rescan every chain from `BRIDGE_SIGNER_BELDEX_START_HEIGHT` /
//! `start_block` (default 0) and lean on the reconciler to skip finished work: one RPC per
//! historical duty, a long stall before new work, and heavy load on the RPCs it shares.
//!
//! A cursor may only be trusted if nothing below it can still be owed, so it is written
//! only when a chain has nothing unfinished. Signed mints and releases live in their own
//! outboxes and survive restarts; what lives only in memory is work not yet signed:
//! duties pending or in flight, duties waiting on an undetermined reconcile, events
//! dropped because this node's key was replaced, and rotations not yet acknowledged on L1.
//! While any of those exists for a chain, its cursor stays where it was, which is never
//! worse than rescanning.
//!
//! A cursor also names the block it stops at, by hash. It is used only when the chain
//! still has that block there: a cursor from another chain (a fresh devnet deploys wBDX at
//! the same address), from another gateway, or from before a reorg is ignored, and the
//! watcher starts from its configured height instead.

use crate::orchestrator::Duty;
use std::io::Write;
use std::path::Path;

/// The last block of a chain that was fully handled, and its hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub height: u64,
    pub hash: [u8; 32],
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn path(dir: &Path, name: &str) -> std::path::PathBuf {
    dir.join(format!("{name}.cursor"))
}

/// Read the cursor saved as `name`, if it was saved for `identity` (the gateway, or the
/// chain and contract). A cursor for another identity is not this one's progress.
pub fn load(dir: &Path, name: &str, identity: &str) -> Result<Option<Cursor>, String> {
    let p = path(dir, name);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", p.display())),
    };
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
    if field("identity ") != Some(identity) {
        return Ok(None);
    }
    let height = field("height ")
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| format!("{}: no height", p.display()))?;
    let hash_hex = field("hash ").ok_or_else(|| format!("{}: no hash", p.display()))?;
    let hash = (hash_hex.len() == 64)
        .then(|| (0..32).map(|i| u8::from_str_radix(&hash_hex[2 * i..2 * i + 2], 16)).collect::<Result<Vec<u8>, _>>())
        .and_then(Result::ok)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("{}: bad hash", p.display()))?;
    Ok(Some(Cursor { height, hash }))
}

/// Save a cursor, atomically: a crash leaves the old one or the new one, never half.
pub fn save(dir: &Path, name: &str, identity: &str, c: &Cursor) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let p = path(dir, name);
    let tmp = p.with_extension(format!("cursor.{}.tmp", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        writeln!(f, "identity {identity}\nheight {}\nhash {}", c.height, hex(&c.hash))
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &p).map_err(|e| format!("rename {}: {e}", p.display()))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Whether the Beldex side may record progress: no mint is unfinished. `unfinished` is
/// every duty not done, plus any waiting on an undetermined reconcile.
pub fn mints_settled<'a>(unfinished: impl IntoIterator<Item = &'a Duty>) -> bool {
    !unfinished.into_iter().any(|d| matches!(d, Duty::Mint(_)))
}

/// Whether EVM chain `chain` may record progress: no release from it is unfinished.
pub fn releases_settled<'a>(chain: u64, unfinished: impl IntoIterator<Item = &'a Duty>) -> bool {
    !unfinished.into_iter().any(|d| matches!(d, Duty::Release(r) if r.chain.0 == chain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;
    use crate::watch::{MintEvent, ReleaseEvent};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("bx-cursor-{tag}-{}", std::process::id()))
    }

    #[test]
    fn a_cursor_reloads_only_for_its_own_identity() {
        let dir = tmpdir("roundtrip");
        let c = Cursor { height: 1234, hash: [0xAB; 32] };
        save(&dir, "evm-31337", "evm chain 31337 contract e7f1", &c).unwrap();
        assert_eq!(load(&dir, "evm-31337", "evm chain 31337 contract e7f1").unwrap(), Some(c));
        assert_eq!(load(&dir, "evm-31337", "evm chain 31337 contract 9999").unwrap(), None, "another contract");
        assert_eq!(load(&dir, "evm-1", "evm chain 1 contract e7f1").unwrap(), None, "never saved");
        // Saving again replaces it in place.
        let later = Cursor { height: 2000, hash: [0xCD; 32] };
        save(&dir, "evm-31337", "evm chain 31337 contract e7f1", &later).unwrap();
        assert_eq!(load(&dir, "evm-31337", "evm chain 31337 contract e7f1").unwrap(), Some(later));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_cursor_is_an_error_not_a_guess() {
        let dir = tmpdir("damaged");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("beldex.cursor"), "identity gw\nheight 10\nhash zz\n").unwrap();
        assert!(load(&dir, "beldex", "gw").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_chain_records_progress_only_with_nothing_unfinished() {
        let mint = Duty::Mint(MintEvent { beldex_txid: [1; 32], output_index: 0, dst_chain: ChainId(56), to: [0; 20], amount: 1 });
        let release = |c: u64| {
            Duty::Release(ReleaseEvent { evm_txid: [2; 32], log_index: 0, chain: ChainId(c), amount: 1, beldex_recipient: vec![] })
        };
        assert!(mints_settled(&[]));
        assert!(!mints_settled(&[mint.clone()]));
        assert!(mints_settled(&[release(1)]), "a release does not hold the Beldex side");
        assert!(!releases_settled(1, &[release(1)]));
        assert!(releases_settled(1, &[release(56), mint]), "only this chain's releases count");
    }
}

//! Which share set a signer serves, and moving a standby set into the live place.
//!
//! A signer is meant to run under a supervisor (systemd, Docker) that restarts it. A node
//! runs two: a live signer on its live share directory and a standby signer on its standby
//! one. When a key changes hands, the shares move, and each signer follows them by
//! restarting rather than swapping keys in a running process:
//!  - a signer whose directory holds no share set waits for one, instead of exiting into a
//!    restart loop (a node not on the current committee);
//!  - a signer whose directory's share set changes under it exits, so the supervisor
//!    restarts it on the new set (a rotation's or takeover's shares were promoted);
//!  - a standby signer whose key every chain now answers to promotes its own set into the
//!    live directory, archiving the old one, and exits.

use std::path::{Path, PathBuf};

/// The exit code that asks the supervisor for a restart: EX_TEMPFAIL.
pub const RESTART_EXIT_CODE: i32 = 75;

/// The first file in `dir` whose name starts with `prefix` and ends with `suffix`.
fn find(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
        })
        .collect();
    names.sort();
    names.into_iter().next()
}

/// The identity of the share set in `dir`: its Pevm group key and Pgw group key, as written
/// by the DKG. None when either is missing: no complete share set is there.
pub fn fingerprint(dir: &Path) -> Option<Vec<u8>> {
    let pevm = std::fs::read(find(dir, "pevm-", ".groupkey")?).ok()?;
    let pgw = std::fs::read(find(dir, "pgw-", ".groupvk")?).ok()?;
    let mut fp = pevm;
    fp.extend_from_slice(&pgw);
    Some(fp)
}

/// Move the standby share set into the live place: the live directory, if there is one, is
/// renamed to `<live>.retired-<now_secs>` (never deleted: it is the only record of that key's
/// shares), then the standby directory is renamed to the live one. Returns where the old set
/// went. Both are single renames on one filesystem, so a crash leaves either the old state
/// or the new one, and a live signer reading the directory sees one whole set or none.
pub fn promote(standby: &Path, live: &Path, now_secs: u64) -> Result<Option<PathBuf>, String> {
    if fingerprint(standby).is_none() {
        return Err(format!("{} holds no share set to promote", standby.display()));
    }
    let archived = if live.exists() {
        let mut to = live.as_os_str().to_owned();
        to.push(format!(".retired-{now_secs}"));
        let to = PathBuf::from(to);
        if to.exists() {
            return Err(format!("{} already exists", to.display()));
        }
        std::fs::rename(live, &to).map_err(|e| format!("archive {}: {e}", live.display()))?;
        Some(to)
    } else {
        None
    };
    std::fs::rename(standby, live)
        .map_err(|e| format!("move {} to {}: {e}", standby.display(), live.display()))?;
    Ok(archived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(dir: &Path, pevm: &[u8], pgw: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("pevm-3.groupkey"), pevm).unwrap();
        std::fs::write(dir.join("pgw-3.groupvk"), pgw).unwrap();
        std::fs::write(dir.join("pevm-3.keyshare"), b"share").unwrap();
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bx-sharewatch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_share_set_is_known_by_its_group_keys() {
        let d = tmp("fp");
        assert_eq!(fingerprint(&d.join("shares")), None, "no directory");
        std::fs::create_dir_all(d.join("shares")).unwrap();
        std::fs::write(d.join("shares/pevm-3.groupkey"), b"A").unwrap();
        assert_eq!(fingerprint(&d.join("shares")), None, "half a set");
        tree(&d.join("shares"), b"A", b"B");
        let one = fingerprint(&d.join("shares")).unwrap();
        tree(&d.join("other"), b"A", b"C");
        assert_ne!(Some(one), fingerprint(&d.join("other")), "another Pgw key is another set");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn promoting_archives_the_live_set_and_moves_the_standby_in() {
        let d = tmp("promote");
        let (live, standby) = (d.join("shares"), d.join("shares-standby"));
        tree(&live, b"OLD", b"old");
        tree(&standby, b"NEW", b"new");
        let new_fp = fingerprint(&standby).unwrap();
        let old_fp = fingerprint(&live).unwrap();

        let archived = promote(&standby, &live, 1234).unwrap().unwrap();
        assert_eq!(archived, d.join("shares.retired-1234"));
        assert_eq!(fingerprint(&live), Some(new_fp));
        assert_eq!(fingerprint(&archived), Some(old_fp));
        assert!(!standby.exists());

        // Nothing left to promote; and a node with no live set just receives one.
        assert!(promote(&standby, &live, 1235).is_err());
        let (live2, standby2) = (d.join("b/shares"), d.join("b/shares-standby"));
        tree(&standby2, b"NEW", b"new");
        assert_eq!(promote(&standby2, &live2, 1).unwrap(), None);
        assert!(fingerprint(&live2).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }
}

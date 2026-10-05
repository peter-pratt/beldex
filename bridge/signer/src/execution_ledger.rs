//! Durable record of every DKG execution id this node has started, so none runs twice.
//!
//! A DKG run's execution id is derived from values every participant agrees on — the leg,
//! the committee and the key generation — so that all of them derive the same one. That
//! also means a run retried after a failure, with the same committee and generation,
//! derives the *same* id again. cggmp21 requires the id to be unique per execution: it
//! binds every message to one run, and a reused id lets messages from the failed run be
//! taken as part of the retry. The FROST leg has no execution id of its own and relies on
//! the same session identity, with the same problem.
//!
//! Nothing stopped the reuse. The launch scripts ask the operator not to repeat a key
//! generation and say the record is "in the run log", but re-running a failed DKG with the
//! same arguments is the natural thing to do.
//!
//! So before a run sends its first protocol message, its id is reserved here: a file
//! created with `create_new`, fsynced with its directory. A second reservation of the same
//! id fails, and the run is refused before it talks to anyone. A failed run therefore
//! needs a fresh key generation, agreed by every participant. Reservations are never
//! removed: an id is spent once any message has gone out under it.

use std::io::ErrorKind;
use std::path::Path;

/// Reserve `id` for `label` in `dir`. Fails if it was ever reserved before, or if the
/// reservation cannot be made durable — a run that cannot record its id must not start.
pub fn reserve(dir: &Path, label: &str, id: &[u8; 32]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{label}-{name}"));
    let file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            return Err(format!(
                "{label} execution {name} has already been started on this node (recorded in \
                 {}). An execution id must never be reused: run again with a fresh \
                 BRIDGE_SIGNER_DKG_KEYGEN, the same on every participant",
                dir.display()
            ));
        }
        Err(e) => return Err(format!("reserve {}: {e}", path.display())),
    };
    file.sync_all().map_err(|e| format!("fsync {}: {e}", path.display()))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("bx-exec-ledger-{tag}-{}", std::process::id()))
    }

    #[test]
    fn an_id_can_be_reserved_once() {
        let dir = tmpdir("once");
        reserve(&dir, "pevm-keygen", &[1; 32]).unwrap();
        let e = reserve(&dir, "pevm-keygen", &[1; 32]).unwrap_err();
        assert!(e.contains("fresh BRIDGE_SIGNER_DKG_KEYGEN"), "{e}");
        // Another id, or the same id for another phase, is a different execution.
        reserve(&dir, "pevm-keygen", &[2; 32]).unwrap();
        reserve(&dir, "pevm-aux", &[1; 32]).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The point of writing it down: a restarted node still refuses the id.
    #[test]
    fn a_reservation_survives_the_process() {
        let dir = tmpdir("survives");
        reserve(&dir, "pgw-dkg", &[7; 32]).unwrap();
        assert!(dir.join(format!("pgw-dkg-{}", "07".repeat(32))).exists());
        assert!(reserve(&dir, "pgw-dkg", &[7; 32]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_reservations_have_exactly_one_winner() {
        let dir = tmpdir("race");
        let wins: usize = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..8).map(|_| sc.spawn(|| reserve(&dir, "pevm-keygen", &[9; 32]).is_ok())).collect();
            hs.into_iter().map(|h| h.join().unwrap() as usize).sum()
        });
        assert_eq!(wins, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! At-rest protection for the key-share files in a share directory.
//!
//! A share directory holds two kinds of file:
//!
//! * **secret** — `pgw-<i>.keypackage` and `pevm-<i>.keyshare`, this member's shares of
//!   the gateway and mint keys. Four of them from different members control the bridge.
//! * **public** — `pgw-<i>.pubkeypackage`, `pgw-<i>.groupvk`, `pevm-<i>.groupkey`: the
//!   group keys and verifying shares, which the chain and every member already know.
//!
//! Secret files used to be written in plaintext unless an encryption key happened to be
//! set. A share then leaked with every copy of the disk: a backup, a snapshot, a reused
//! disk, a laptop holding a copy of the node directory. Shares stay valid until the keys
//! rotate, so an attacker can collect four of them over months, from four unrelated
//! leaks, and nothing on any node shows it.
//!
//! So a secret file is always sealed, and a plaintext one is refused, unless a test
//! network explicitly allows it (`BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES=1`):
//!
//! * XChaCha20-Poly1305 under a 32-byte key, with the file's own name as associated data
//!   (`BXSHARE2`), so a sealed file opens only under the name it was written as and one
//!   member's or one leg's share cannot be swapped in for another.
//! * The key comes from outside the share directory: a key file
//!   (`BRIDGE_SIGNER_SHARE_KEY_FILE`, owner-only, not inside the share directory), a
//!   systemd credential (`$CREDENTIALS_DIRECTORY/bridge-share-key`), or, discouraged,
//!   `BRIDGE_SIGNER_SHARE_KEY`. A copy of the share directory alone is then useless.
//! * Public files are written readable, since scripts compare them, and a member never
//!   takes its group keys from them: it derives them from its sealed share and requires
//!   the public file to agree.
//!
//! Older trees still open: plaintext (with a test network's permission) and `BXSHARE1`
//! (sealed with no associated data). [`protect_dir`] rewrites a tree in the current form.
//!
//! The key still lives on the host, so this protects every copy that leaves the machine,
//! not a running node an attacker already controls. Non-exportable custody (a vault, an
//! HSM, an enclave) is what closes that, and is separate work.

use crate::ffi::{aead_decrypt, aead_decrypt_ad, aead_encrypt_ad, AEAD_KEY_LEN};
use std::path::{Path, PathBuf};

/// Sealed with no associated data. Read for compatibility, never written.
pub const MAGIC_V1: &[u8; 8] = b"BXSHARE1";
/// Sealed with the file name as associated data.
pub const MAGIC_V2: &[u8; 8] = b"BXSHARE2";

/// systemd `LoadCredential=` name looked for in `$CREDENTIALS_DIRECTORY`.
pub const CREDENTIAL_NAME: &str = "bridge-share-key";

pub type ShareKey = [u8; AEAD_KEY_LEN];

/// Whether `name` is a secret share file (as opposed to public group-key material).
pub fn is_secret(name: &str) -> bool {
    name.ends_with(".keypackage") || name.ends_with(".keyshare")
}

/// Whether `name` is public material written beside the shares.
pub fn is_public(name: &str) -> bool {
    name.ends_with(".pubkeypackage") || name.ends_with(".groupvk") || name.ends_with(".groupkey")
}

/// `BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES=1`: a test network accepting plaintext shares.
pub fn plaintext_allowed() -> bool {
    std::env::var("BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES").map(|v| v == "1").unwrap_or(false)
}

fn file_name(path: &Path) -> Result<&str, String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{}: not a share file name", path.display()))
}

fn ad_for(name: &str) -> Vec<u8> {
    format!("beldex-bridge-share-v2:{name}").into_bytes()
}

fn parse_key_hex(text: &str, what: &str) -> Result<ShareKey, String> {
    let t = text.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.len() != 64 {
        return Err(format!("{what} must be 64 hex characters (32 bytes)"));
    }
    let mut k = [0u8; AEAD_KEY_LEN];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(|_| format!("{what} is not hex"))?;
    }
    if k == [0u8; AEAD_KEY_LEN] {
        return Err(format!("{what} is all zeros"));
    }
    Ok(k)
}

/// Read a key file, refusing one that would not keep the shares safe: a symlink (which
/// can be pointed anywhere later), anything but a regular file, a file group or other
/// users can read, or a file inside the share directory (which every copy of that
/// directory would then carry along with the shares).
pub fn read_key_file(path: &Path, share_dir: Option<&Path>) -> Result<ShareKey, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("share key file {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!("share key file {} must be a regular file, not a link", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "share key file {} is readable by group or others; chmod 600 it",
                path.display()
            ));
        }
    }
    if let Some(dir) = share_dir {
        if let (Ok(k), Ok(d)) = (path.canonicalize(), dir.canonicalize()) {
            if k.starts_with(&d) {
                return Err(format!(
                    "share key file {} is inside the share directory {}; keep it elsewhere, or \
                     every copy of the shares carries their key",
                    path.display(),
                    dir.display()
                ));
            }
        }
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_key_hex(&text, &format!("share key file {}", path.display()))
}

/// Find the share key from explicit sources, in order: a key file, a systemd credential
/// directory, an environment value. `None` when none is configured.
pub fn find_key(
    key_file: Option<&Path>,
    credentials_dir: Option<&Path>,
    env_hex: Option<&str>,
    share_dir: Option<&Path>,
) -> Result<Option<ShareKey>, String> {
    if let Some(f) = key_file {
        return read_key_file(f, share_dir).map(Some);
    }
    if let Some(dir) = credentials_dir {
        let cred = dir.join(CREDENTIAL_NAME);
        if cred.exists() {
            // systemd places credentials in a private, read-only directory it owns.
            let text = std::fs::read_to_string(&cred).map_err(|e| format!("read {}: {e}", cred.display()))?;
            return parse_key_hex(&text, &format!("credential {}", cred.display())).map(Some);
        }
    }
    if let Some(hex) = env_hex.filter(|h| !h.trim().is_empty()) {
        return parse_key_hex(hex, "BRIDGE_SIGNER_SHARE_KEY").map(Some);
    }
    Ok(None)
}

/// [`find_key`] from this process's configuration.
pub fn configured_key(share_dir: Option<&Path>) -> Result<Option<ShareKey>, String> {
    let file = std::env::var("BRIDGE_SIGNER_SHARE_KEY_FILE").ok().filter(|s| !s.trim().is_empty());
    let creds = std::env::var("CREDENTIALS_DIRECTORY").ok().filter(|s| !s.trim().is_empty());
    let env = std::env::var("BRIDGE_SIGNER_SHARE_KEY").ok();
    if file.is_none() && env.as_deref().is_some_and(|h| !h.trim().is_empty()) {
        static WARN: std::sync::Once = std::sync::Once::new();
        WARN.call_once(|| {
            eprintln!(
                "WARNING: the share key comes from BRIDGE_SIGNER_SHARE_KEY, which any process of \
                 this user can read from the environment and which ends up in unit files and \
                 scripts. Prefer BRIDGE_SIGNER_SHARE_KEY_FILE or a systemd credential."
            )
        });
    }
    find_key(file.as_deref().map(Path::new), creds.as_deref().map(Path::new), env.as_deref(), share_dir)
}

fn no_key_error() -> String {
    "no share key: set BRIDGE_SIGNER_SHARE_KEY_FILE to an owner-only file outside the share \
     directory holding 64 hex characters (`beldex-bridge-signer new-share-key <path>` makes \
     one), or provide the systemd credential `bridge-share-key`. Shares are never written or \
     read in plaintext unless BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES=1 (test networks only)."
        .to_string()
}

/// The configured key, or `None` where a test network allows plaintext; otherwise an
/// error saying how to configure one. For checking before work that ends in writing
/// shares, so a DKG is not run only to fail at the end.
pub fn require_key(share_dir: Option<&Path>) -> Result<Option<ShareKey>, String> {
    match configured_key(share_dir)? {
        Some(k) => Ok(Some(k)),
        None if plaintext_allowed() => Ok(None),
        None => Err(no_key_error()),
    }
}

/// Seal `plaintext` for the file called `name`.
pub fn seal(key: &ShareKey, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let ct = aead_encrypt_ad(key, plaintext, &ad_for(name)).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(MAGIC_V2.len() + ct.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// How a file on disk was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    Plaintext,
    SealedV1,
    SealedV2,
}

/// Classify and, if sealed, open `raw` read from the file called `name`.
pub fn open(key: Option<&ShareKey>, name: &str, raw: &[u8]) -> Result<(Vec<u8>, Stored), String> {
    let (magic, stored) = if raw.starts_with(MAGIC_V2) {
        (MAGIC_V2, Stored::SealedV2)
    } else if raw.starts_with(MAGIC_V1) {
        (MAGIC_V1, Stored::SealedV1)
    } else {
        return Ok((raw.to_vec(), Stored::Plaintext));
    };
    let key = key.ok_or_else(|| format!("{name} is sealed but {}", no_key_error()))?;
    let body = &raw[magic.len()..];
    let plain = match stored {
        Stored::SealedV2 => aead_decrypt_ad(key, body, &ad_for(name)),
        _ => aead_decrypt(key, body),
    }
    .map_err(|_| {
        format!("{name} does not open with this share key (wrong key, an altered file, or a file renamed from another share)")
    })?;
    Ok((plain, stored))
}

/// Replace `path` with `bytes`, owner-only: a unique scratch file, fsync, rename, then
/// fsync the directory. A crash leaves the old file or the new one, never half of either.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = PathBuf::from(format!("{}.{}-{seq}.tmp", path.display(), std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename {} -> {}: {e}", tmp.display(), path.display()));
    }
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("fsync {}: {e}", parent.display()))?;
    }
    Ok(())
}

/// Write a secret share file with an explicit key policy.
pub fn write_secret_with(path: &Path, bytes: &[u8], key: Option<&ShareKey>, plaintext_ok: bool) -> Result<(), String> {
    let name = file_name(path)?;
    match key {
        Some(k) => write_atomic(path, &seal(k, name, bytes)?),
        None if plaintext_ok => {
            eprintln!("WARNING: writing {} in PLAINTEXT (BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES=1)", path.display());
            write_atomic(path, bytes)
        }
        None => Err(no_key_error()),
    }
}

/// Read a secret share file with an explicit key policy. Plaintext is refused unless
/// `plaintext_ok`, so a share that was never sealed cannot be used by accident.
pub fn read_secret_with(path: &Path, key: Option<&ShareKey>, plaintext_ok: bool) -> Result<Vec<u8>, String> {
    let name = file_name(path)?;
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let (plain, stored) = open(key, name, &raw)?;
    if stored == Stored::Plaintext && !plaintext_ok {
        return Err(format!(
            "{} is stored in PLAINTEXT. Seal it with `beldex-bridge-signer protect-shares` \
             (with the share key configured), or set BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES=1 on a \
             test network.",
            path.display()
        ));
    }
    Ok(plain)
}

/// Read public material. Older trees sealed these too; such a file is opened with the
/// key if one is configured.
pub fn read_public_with(path: &Path, key: Option<&ShareKey>) -> Result<Vec<u8>, String> {
    let name = file_name(path)?;
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    open(key, name, &raw).map(|(plain, _)| plain)
}

/// Write a secret share file using this process's configuration.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let key = configured_key(path.parent())?;
    write_secret_with(path, bytes, key.as_ref(), plaintext_allowed())
}

/// Read a secret share file using this process's configuration.
pub fn read_secret(path: &Path) -> Result<Vec<u8>, String> {
    let key = configured_key(path.parent())?;
    read_secret_with(path, key.as_ref(), plaintext_allowed())
}

/// Write public material: readable bytes, owner-only, atomically.
pub fn write_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_atomic(path, bytes)
}

/// Read public material using this process's configuration.
pub fn read_public(path: &Path) -> Result<Vec<u8>, String> {
    let key = configured_key(path.parent())?;
    read_public_with(path, key.as_ref())
}

/// What [`protect_dir`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectReport {
    /// Secret files sealed from plaintext.
    pub sealed: Vec<String>,
    /// Secret files re-sealed from `BXSHARE1` to `BXSHARE2`.
    pub upgraded: Vec<String>,
    /// Secret files already in the current form (and opening under this key).
    pub current: Vec<String>,
    /// Public files that older code had sealed, rewritten readable.
    pub unsealed_public: Vec<String>,
}

/// Bring every share file in `dir` to the current form under `key`: seal plaintext
/// secrets, re-seal `BXSHARE1` ones with their name bound, check current ones open under
/// this key, and make sealed public files readable again. Each new file is checked to
/// open to the same bytes before it replaces the old one. Fails, changing nothing more,
/// at the first file that cannot be opened.
pub fn protect_dir(dir: &Path, key: &ShareKey) -> Result<ProtectReport, String> {
    let mut report = ProtectReport::default();
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_secret(n) || is_public(n))
        .collect();
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let raw = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let (plain, stored) = open(Some(key), &name, &raw)?;
        if is_secret(&name) {
            if stored == Stored::SealedV2 {
                report.current.push(name);
                continue;
            }
            let sealed = seal(key, &name, &plain)?;
            let (check, _) = open(Some(key), &name, &sealed)?;
            if check != plain {
                return Err(format!("{name}: sealed copy did not open to the same bytes; left unchanged"));
            }
            write_atomic(&path, &sealed)?;
            match stored {
                Stored::Plaintext => report.sealed.push(name),
                _ => report.upgraded.push(name),
            }
        } else if stored != Stored::Plaintext {
            write_atomic(&path, &plain)?;
            report.unsealed_public.push(name);
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: ShareKey = [0x11; 32];
    const OTHER: ShareKey = [0x22; 32];

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bx-share-file-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The point: a copy of the directory does not contain the share.
    #[test]
    fn a_secret_share_is_sealed_on_disk_and_opens_with_its_key() {
        let d = tmpdir("sealed");
        let p = d.join("pevm-3.keyshare");
        let secret = b"the pevm key share bytes";
        write_secret_with(&p, secret, Some(&KEY), false).unwrap();

        let on_disk = std::fs::read(&p).unwrap();
        assert!(on_disk.starts_with(MAGIC_V2));
        assert!(!on_disk.windows(secret.len()).any(|w| w == secret), "never in the clear");
        assert_eq!(read_secret_with(&p, Some(&KEY), false).unwrap(), secret);
        assert!(read_secret_with(&p, Some(&OTHER), false).is_err(), "wrong key fails loudly");
        assert!(read_secret_with(&p, None, false).unwrap_err().contains("no share key"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Without a key, nothing is written; with permission, a test network can.
    #[test]
    fn plaintext_is_refused_unless_a_test_network_allows_it() {
        let d = tmpdir("plain");
        let p = d.join("pgw-0.keypackage");
        assert!(write_secret_with(&p, b"x", None, false).unwrap_err().contains("no share key"));
        assert!(!p.exists(), "nothing written");

        std::fs::write(&p, b"legacy plaintext share").unwrap();
        let e = read_secret_with(&p, Some(&KEY), false).unwrap_err();
        assert!(e.contains("PLAINTEXT"), "{e}");
        assert_eq!(read_secret_with(&p, None, true).unwrap(), b"legacy plaintext share");
        write_secret_with(&p, b"test only", None, true).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"test only");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The file name is bound: one member's or one leg's sealed share renamed into place
    /// of another does not open.
    #[test]
    fn a_sealed_share_does_not_open_under_another_name() {
        let d = tmpdir("swap");
        let a = d.join("pevm-1.keyshare");
        let b = d.join("pevm-2.keyshare");
        write_secret_with(&a, b"share one", Some(&KEY), false).unwrap();
        std::fs::copy(&a, &b).unwrap();
        let e = read_secret_with(&b, Some(&KEY), false).unwrap_err();
        assert!(e.contains("renamed"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_v1_share_still_opens() {
        let d = tmpdir("v1");
        let p = d.join("pgw-2.keypackage");
        let mut v1 = MAGIC_V1.to_vec();
        v1.extend_from_slice(&crate::ffi::aead_encrypt(&KEY, b"older sealed share").unwrap());
        std::fs::write(&p, &v1).unwrap();
        assert_eq!(read_secret_with(&p, Some(&KEY), false).unwrap(), b"older sealed share");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Migration: every kind of older file ends up in the current form, opening to the
    /// same bytes; public files end up readable for the scripts that compare them.
    #[test]
    fn protect_dir_brings_a_tree_to_the_current_form() {
        let d = tmpdir("protect");
        std::fs::write(d.join("pevm-0.keyshare"), b"plain share").unwrap();
        let mut v1 = MAGIC_V1.to_vec();
        v1.extend_from_slice(&crate::ffi::aead_encrypt(&KEY, b"v1 share").unwrap());
        std::fs::write(d.join("pgw-0.keypackage"), &v1).unwrap();
        let mut sealed_public = MAGIC_V1.to_vec();
        sealed_public.extend_from_slice(&crate::ffi::aead_encrypt(&KEY, &[7u8; 33]).unwrap());
        std::fs::write(d.join("pevm-0.groupkey"), &sealed_public).unwrap();
        std::fs::write(d.join("pgw-0.groupvk"), [9u8; 32]).unwrap();
        std::fs::write(d.join("key_committee.json"), b"{}").unwrap();

        let r = protect_dir(&d, &KEY).unwrap();
        assert_eq!(r.sealed, vec!["pevm-0.keyshare"]);
        assert_eq!(r.upgraded, vec!["pgw-0.keypackage"]);
        assert_eq!(r.unsealed_public, vec!["pevm-0.groupkey"]);

        assert_eq!(read_secret_with(&d.join("pevm-0.keyshare"), Some(&KEY), false).unwrap(), b"plain share");
        assert!(std::fs::read(d.join("pgw-0.keypackage")).unwrap().starts_with(MAGIC_V2));
        assert_eq!(std::fs::read(d.join("pevm-0.groupkey")).unwrap(), [7u8; 33]);
        assert_eq!(std::fs::read(d.join("key_committee.json")).unwrap(), b"{}", "other files untouched");

        // Idempotent.
        let again = protect_dir(&d, &KEY).unwrap();
        assert_eq!(again.current.len(), 2);
        assert!(again.sealed.is_empty() && again.upgraded.is_empty());
        // And the wrong key changes nothing.
        let before = std::fs::read(d.join("pevm-0.keyshare")).unwrap();
        assert!(protect_dir(&d, &OTHER).is_err());
        assert_eq!(std::fs::read(d.join("pevm-0.keyshare")).unwrap(), before);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The key file must not be readable by others, must not be a link, and must not
    /// sit inside the share directory it protects.
    #[cfg(unix)]
    #[test]
    fn a_key_file_must_be_private_and_kept_apart_from_the_shares() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmpdir("keyfile");
        let shares = root.join("shares");
        std::fs::create_dir_all(&shares).unwrap();
        let good = root.join("share.key");
        std::fs::write(&good, "11".repeat(32)).unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key_file(&good, Some(&shares)).unwrap(), KEY);

        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key_file(&good, Some(&shares)).unwrap_err().contains("chmod 600"));
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();

        let inside = shares.join("share.key");
        std::fs::write(&inside, "11".repeat(32)).unwrap();
        std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_key_file(&inside, Some(&shares)).unwrap_err().contains("inside the share directory"));

        let link = root.join("link.key");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(read_key_file(&link, Some(&shares)).unwrap_err().contains("not a link"));

        let zero = root.join("zero.key");
        std::fs::write(&zero, "00".repeat(32)).unwrap();
        std::fs::set_permissions(&zero, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_key_file(&zero, None).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn key_sources_are_taken_in_order() {
        let root = tmpdir("sources");
        let creds = root.join("creds");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join(CREDENTIAL_NAME), "22".repeat(32)).unwrap();
        let env = "33".repeat(32);
        assert_eq!(find_key(None, Some(&creds), Some(&env), None).unwrap(), Some(OTHER), "credential before env");
        assert_eq!(find_key(None, None, Some(&env), None).unwrap(), Some([0x33; 32]));
        assert_eq!(find_key(None, None, None, None).unwrap(), None);
        assert!(find_key(None, None, Some("xyz"), None).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}

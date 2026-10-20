//! Where `relay` finds its gas key.
//!
//! The gas key pays for mint transactions. It has no bridge authority, but whoever holds it
//! can drain the gas wallet, and a relayer without gas mints nothing. An environment
//! variable is the worst place for it: any process of the same user can read it, and
//! because the signer launches the relayer through a `RELAY_CMD` such as
//! `env RELAYER_GAS_KEY=… beldex-bridge-relayer relay -`, the key also sits in that
//! process's command line, readable by every user on the host, and in the signer's saved
//! settings. So, in order:
//!
//! 1. `RELAYER_GAS_KEY_FILE`: an owner-only file holding the 64 hex characters;
//! 2. the systemd credential `relayer-gas-key` (`LoadCredential=` puts it in
//!    `$CREDENTIALS_DIRECTORY`);
//! 3. `RELAYER_GAS_KEY`, with a warning, for test networks and one-off use.

use std::path::Path;

/// systemd `LoadCredential=` name looked for in `$CREDENTIALS_DIRECTORY`.
pub const CREDENTIAL_NAME: &str = "relayer-gas-key";

/// Where the key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    File,
    Credential,
    Environment,
}

/// The gas key as hex, and where it came from: `file` first, then `creds_dir`'s
/// credential, then `env`.
pub fn find(file: Option<&Path>, creds_dir: Option<&Path>, env: Option<&str>) -> Result<(String, Source), String> {
    if let Some(p) = file {
        return read_owner_only(p).map(|k| (k, Source::File));
    }
    if let Some(d) = creds_dir {
        let p = d.join(CREDENTIAL_NAME);
        if p.exists() {
            // systemd makes credentials readable by the service alone; no mode check.
            let k = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            return Ok((k.trim().to_string(), Source::Credential));
        }
    }
    match env.map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => Ok((k.to_string(), Source::Environment)),
        None => Err(format!(
            "no gas key: set RELAYER_GAS_KEY_FILE to an owner-only file holding the 32-byte hex \
             key, or provide the systemd credential `{CREDENTIAL_NAME}` (RELAYER_GAS_KEY works \
             too, but leaks into process listings and saved settings)"
        )),
    }
}

/// [`find`] from this process's environment.
pub fn configured() -> Result<(String, Source), String> {
    let nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let file = nonempty("RELAYER_GAS_KEY_FILE");
    let creds = nonempty("CREDENTIALS_DIRECTORY");
    let env = std::env::var("RELAYER_GAS_KEY").ok();
    find(file.as_deref().map(|s| Path::new(s.trim())), creds.as_deref().map(Path::new), env.as_deref())
}

fn read_owner_only(p: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is readable by other users (mode {mode:o}); make it owner-only (chmod 600)",
                p.display()
            ));
        }
    }
    let k = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(k.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bx-gaskey-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_file_comes_first_then_a_credential_then_the_environment() {
        let d = tmp("order");
        let file = d.join("gas.key");
        std::fs::write(&file, "aa\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let creds = d.join("creds");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join(CREDENTIAL_NAME), "bb").unwrap();

        assert_eq!(find(Some(&file), Some(&creds), Some("cc")).unwrap(), ("aa".into(), Source::File));
        assert_eq!(find(None, Some(&creds), Some("cc")).unwrap(), ("bb".into(), Source::Credential));
        assert_eq!(find(None, Some(&d), Some(" cc ")).unwrap(), ("cc".into(), Source::Environment), "no credential there");
        assert!(find(None, None, Some("  ")).is_err());
        assert!(find(None, None, None).unwrap_err().contains("RELAYER_GAS_KEY_FILE"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("mode");
        let file = d.join("gas.key");
        std::fs::write(&file, "aa").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(find(Some(&file), None, Some("cc")).unwrap_err().contains("readable by other users"));
        let _ = std::fs::remove_dir_all(&d);
    }
}

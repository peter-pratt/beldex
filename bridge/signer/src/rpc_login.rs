//! Logging in to a local Beldex wallet RPC (the rotation-ack wallet).
//!
//! beldex-wallet-rpc authenticates with HTTP Basic: `--rpc-login user:password`, or, with
//! neither that nor `--disable-rpc-login`, a random login it writes to an owner-only file
//! named `beldex-wallet-rpc.<port>.login`. Without a login, anything that can reach the
//! port can spend from the wallet. The signer reads the login from a file
//! (`BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE`) rather than the environment, and only from a
//! file other users cannot read.

use std::path::Path;

/// Read `user:password` from `path`. The file must be readable by its owner only (on
/// unix), and hold exactly one `user:password` line.
pub fn read_login_file(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is readable by other users (mode {mode:o}); make it owner-only (chmod 600)",
                path.display()
            ));
        }
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let login = text.trim();
    match login.split_once(':') {
        Some((user, pass)) if !user.is_empty() && !pass.is_empty() && !login.contains('\n') => {
            Ok(login.to_string())
        }
        _ => Err(format!("{} must hold one line, user:password", path.display())),
    }
}

/// The `Authorization` header value for HTTP Basic with `login` (`user:password`).
pub fn basic_auth_header(login: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = login.as_bytes();
    let mut out = String::with_capacity(6 + b.len().div_ceil(3) * 4);
    out.push_str("Basic ");
    for chunk in b.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_rfc_4648_base64() {
        assert_eq!(basic_auth_header("user:pass"), "Basic dXNlcjpwYXNz");
        assert_eq!(basic_auth_header("a:b"), "Basic YTpi");
        assert_eq!(basic_auth_header("ab:c"), "Basic YWI6Yw==");
        assert_eq!(basic_auth_header("beldex:Zm9v+/="), "Basic YmVsZGV4OlptOXYrLz0=");
    }

    #[test]
    fn a_login_file_must_be_owner_only_and_hold_user_and_password() {
        let dir = std::env::temp_dir().join(format!("bx-login-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("wallet.login");
        std::fs::write(&p, "beldex:secret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_login_file(&p).unwrap_err().contains("readable by other users"));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_login_file(&p).unwrap(), "beldex:secret");
        for bad in ["nopassword", ":secret", "beldex:", "a:b\nc:d"] {
            std::fs::write(&p, bad).unwrap();
            assert!(read_login_file(&p).is_err(), "{bad:?}");
        }
        assert!(read_login_file(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

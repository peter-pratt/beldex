//! Test-network settings are refused on a public network.
//!
//! The signer has settings that exist for local devnets and nothing else: a mesh without
//! CURVE, plaintext shares, a share key read from the environment, EVM burns settled on
//! depth alone, Beldex deposits settled on a confirmation count when no checkpoint exists.
//! Each used to print a warning and carry on, so one copied unit file or a stray variable
//! put a production signer on test-network security with nothing stopping it.
//!
//! Now a signer using any of them asks its own daemon which network it is on (the
//! `nettype` in `bridge.committee`) and runs only on a devnet or fakechain. On mainnet or
//! testnet it refuses, naming every setting at fault; and when the daemon does not say
//! (one from before this check), it refuses too, because it cannot confirm a test network.
//! A signer using none of them never asks.

/// The Beldex network a daemon reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Fakechain,
}

impl Network {
    pub fn from_name(name: &str) -> Option<Network> {
        match name {
            "mainnet" => Some(Network::Mainnet),
            "testnet" => Some(Network::Testnet),
            "devnet" => Some(Network::Devnet),
            "fakechain" => Some(Network::Fakechain),
            _ => None,
        }
    }

    /// Whether test-network settings are allowed here.
    pub fn allows_test_settings(self) -> bool {
        matches!(self, Network::Devnet | Network::Fakechain)
    }
}

/// The `nettype` of a `bridge.committee` reply, if it has one.
pub fn network_of_committee_reply(json: &str) -> Option<Network> {
    let pat = "\"nettype\":\"";
    let i = json.find(pat)? + pat.len();
    let rest = &json[i..];
    Network::from_name(&rest[..rest.find('"')?])
}

/// Refuse `relaxations` (each a short description of a test-network setting in use)
/// unless `network` is a test network.
pub fn enforce(network: Option<Network>, relaxations: &[String]) -> Result<(), String> {
    if relaxations.is_empty() {
        return Ok(());
    }
    let list = relaxations.join("; ");
    match network {
        Some(n) if n.allows_test_settings() => Ok(()),
        Some(n) => Err(format!(
            "refusing to run on {n:?} with test-network settings: {list}. Remove them; they \
             exist for local devnets only"
        )),
        None => Err(format!(
            "test-network settings in use ({list}), and the daemon did not say which network \
             this is (a beldexd from before this check). Refusing: they are allowed only on a \
             confirmed devnet"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_network_is_read_from_the_committee_reply() {
        let reply = r#"{"epoch":3,"members":[],"nettype":"devnet","threshold":4}"#;
        assert_eq!(network_of_committee_reply(reply), Some(Network::Devnet));
        assert_eq!(network_of_committee_reply(r#"{"nettype":"mainnet"}"#), Some(Network::Mainnet));
        assert_eq!(network_of_committee_reply(r#"{"epoch":3}"#), None, "an older daemon");
        assert_eq!(network_of_committee_reply(r#"{"nettype":"moonnet"}"#), None);
    }

    #[test]
    fn test_settings_run_only_on_a_confirmed_test_network() {
        let none: Vec<String> = Vec::new();
        let some = vec!["mesh CURVE disabled".to_string(), "plaintext shares".to_string()];
        for n in [None, Some(Network::Mainnet), Some(Network::Testnet), Some(Network::Devnet)] {
            assert!(enforce(n, &none).is_ok(), "no test settings: runs anywhere");
        }
        assert!(enforce(Some(Network::Devnet), &some).is_ok());
        assert!(enforce(Some(Network::Fakechain), &some).is_ok());
        let e = enforce(Some(Network::Mainnet), &some).unwrap_err();
        assert!(e.contains("mesh CURVE disabled; plaintext shares"), "every setting is named: {e}");
        assert!(enforce(Some(Network::Testnet), &some).is_err());
        assert!(enforce(None, &some).unwrap_err().contains("did not say which network"));
    }
}

//! Supply against reserve, and caps against backing: the bridge's economic invariants,
//! checked by every signer from its own RPCs (H-06).
//!
//! Every wBDX on every EVM chain is a claim on BDX locked in the bridge gateway. Mints
//! follow deposits and releases follow burns, so at any moment
//!
//! ```text
//!     Σ over chains of wBDX totalSupply  <=  gateway balance
//! ```
//!
//! and the difference is what is in flight (deposited, not yet minted; burned, not yet
//! released) plus anything the gateway holds beyond that. A total supply above the
//! balance means wBDX exists that nothing backs: a stolen mint key, a minting bug, or a
//! release that should not have been paid. Nothing used to compare the two, so that
//! would have gone unnoticed until users found they could not redeem.
//!
//! The caps are bounded the same way. A compromised mint key can fill one fixed window
//! just before its boundary and the next just after, so the most it mints before anyone
//! reacts is twice the window cap, on every chain at once. What stands against that is
//! the bond a colluding signing threshold would lose, which consensus reports as
//! `slashable_backing`. So
//!
//! ```text
//!     Σ over chains of 2 * windowMintCap   <=  slashable backing
//!     Σ over chains of bondBackingCapLimit <=  slashable backing
//! ```
//!
//! Each contract enforces the first only against its own `bondBackingCapLimit`, a number
//! governance types in; the second pins that number to what is actually bonded, across
//! all chains together.
//!
//! The signer also refuses to run when the caps it was configured with, the contract's,
//! and consensus's disagree: its own pre-checks would then pass sessions the contract
//! refuses, or the contract would accept burns consensus can never release.
//!
//! What a signer does with a problem is up to the caller: at startup a configuration
//! problem is fatal. While serving, [`SolvencyGuard`] holds signing once a problem has
//! been seen on [`SolvencyGuard::REQUIRED_STREAK`] checks in a row (a mint can land between
//! reading the balance and reading the supply, so a single reading can be off), and lets
//! it go again once a check passes.

use std::fmt;

/// wBDX has 9 decimals so that one unit is one atomic BDX. Every comparison here
/// depends on it.
pub const WBDX_DECIMALS: u8 = 9;

/// One wBDX contract's figures, read from its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFigures {
    pub chain_id: u64,
    pub total_supply: u128,
    pub window_mint_cap: u128,
    pub per_tx_max: u128,
    pub bond_backing_cap_limit: u128,
    pub native_release_max: u128,
    pub decimals: u8,
}

/// The native side's figures, read from consensus (`bridge_get_reserves`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFigures {
    /// BDX locked in the bridge gateway (atomic units).
    pub gateway_balance: u128,
    /// `committee_threshold * bridge_bond`.
    pub slashable_backing: u128,
    /// Consensus's per-withdrawal release maximum.
    pub native_per_tx_max: u128,
}

/// The caps this signer was configured with for one chain (`BRIDGE_SIGNER_EVM_CHAINS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredCaps {
    pub chain_id: u64,
    pub per_tx_max: u128,
    pub per_epoch_cap: u128,
}

/// A broken invariant or a disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// More wBDX exists than the gateway holds.
    Insolvent { supply: u128, reserve: u128 },
    /// Two full windows on every chain exceed what a colluding threshold would lose.
    BurstAboveBacking { exposure: u128, backing: u128 },
    /// The contracts claim more backing between them than is bonded.
    ClaimedBackingAboveBond { claimed: u128, backing: u128 },
    /// A configured chain with no figures (checked, but not read).
    MissingChain(u64),
    /// A contract whose units are not atomic BDX.
    WrongDecimals { chain_id: u64, decimals: u8 },
    /// The signer's caps for a chain differ from its contract's.
    CapMismatch { chain_id: u64, configured: (u128, u128), contract: (u128, u128) },
    /// A contract accepts burns up to a different maximum than consensus releases.
    NativeMaxMismatch { chain_id: u64, contract: u128, native: u128 },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Insolvent { supply, reserve } => write!(
                f,
                "wBDX total supply {supply} exceeds the {reserve} BDX the gateway holds (short by {})",
                supply - reserve
            ),
            Problem::BurstAboveBacking { exposure, backing } => write!(
                f,
                "two full mint windows on every chain ({exposure}) exceed the slashable backing ({backing})"
            ),
            Problem::ClaimedBackingAboveBond { claimed, backing } => write!(
                f,
                "the contracts' bondBackingCapLimit add up to {claimed}, above the slashable backing ({backing})"
            ),
            Problem::MissingChain(c) => write!(f, "chain {c}: no figures read"),
            Problem::WrongDecimals { chain_id, decimals } => write!(
                f,
                "chain {chain_id}: wBDX has {decimals} decimals, not {WBDX_DECIMALS}: its units are not atomic BDX"
            ),
            Problem::CapMismatch { chain_id, configured, contract } => write!(
                f,
                "chain {chain_id}: configured per_tx_max/per_epoch_cap {}/{} but the contract's perTxMax/windowMintCap are {}/{}",
                configured.0, configured.1, contract.0, contract.1
            ),
            Problem::NativeMaxMismatch { chain_id, contract, native } => write!(
                f,
                "chain {chain_id}: the contract accepts burns up to {contract} but consensus releases at most {native}"
            ),
        }
    }
}

/// Everything about caps and backing: whether this signer, the contracts and consensus
/// describe the same limits, and whether those limits fit under the bond.
pub fn check_configuration(
    configured: &[ConfiguredCaps],
    chains: &[ChainFigures],
    native: &NativeFigures,
) -> Vec<Problem> {
    let mut problems = Vec::new();
    for c in configured {
        let Some(f) = chains.iter().find(|f| f.chain_id == c.chain_id) else {
            problems.push(Problem::MissingChain(c.chain_id));
            continue;
        };
        if f.decimals != WBDX_DECIMALS {
            problems.push(Problem::WrongDecimals { chain_id: f.chain_id, decimals: f.decimals });
        }
        if (c.per_tx_max, c.per_epoch_cap) != (f.per_tx_max, f.window_mint_cap) {
            problems.push(Problem::CapMismatch {
                chain_id: f.chain_id,
                configured: (c.per_tx_max, c.per_epoch_cap),
                contract: (f.per_tx_max, f.window_mint_cap),
            });
        }
        if f.native_release_max != native.native_per_tx_max {
            problems.push(Problem::NativeMaxMismatch {
                chain_id: f.chain_id,
                contract: f.native_release_max,
                native: native.native_per_tx_max,
            });
        }
    }
    // Saturating: a sum that overflows u128 is certainly above any backing.
    let exposure = chains.iter().fold(0u128, |a, f| a.saturating_add(f.window_mint_cap.saturating_mul(2)));
    if exposure > native.slashable_backing {
        problems.push(Problem::BurstAboveBacking { exposure, backing: native.slashable_backing });
    }
    let claimed = chains.iter().fold(0u128, |a, f| a.saturating_add(f.bond_backing_cap_limit));
    if claimed > native.slashable_backing {
        problems.push(Problem::ClaimedBackingAboveBond { claimed, backing: native.slashable_backing });
    }
    problems
}

/// Whether the wBDX on all chains together is backed by the gateway's balance.
///
/// Read the balance *before* the supplies: a release only follows its burn, so a release
/// landing between the two reads cannot make the supply look larger than the balance.
pub fn check_solvency(chains: &[ChainFigures], native: &NativeFigures) -> Option<Problem> {
    let supply = chains.iter().fold(0u128, |a, f| a.saturating_add(f.total_supply));
    (supply > native.gateway_balance)
        .then_some(Problem::Insolvent { supply, reserve: native.gateway_balance })
}

/// What a check did to the hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Signing is now held, for this reason.
    Tripped(String),
    /// Signing may resume.
    Cleared,
}

/// Holds signing while the invariants are broken.
///
/// A mint or a release can land between reading the balance and reading the supplies,
/// so one failed check is not proof; [`Self::REQUIRED_STREAK`] in a row are. A check that
/// passes clears the hold at once: the invariants hold again (governance burned the
/// unbacked wBDX, lowered a cap, or the race resolved). A check that could not be made
/// changes nothing either way.
#[derive(Debug, Default)]
pub struct SolvencyGuard {
    streak: u32,
    hold: Option<String>,
}

impl SolvencyGuard {
    pub const REQUIRED_STREAK: u32 = 2;

    pub fn new() -> SolvencyGuard {
        SolvencyGuard::default()
    }

    /// Why signing is held, if it is.
    pub fn hold(&self) -> Option<&str> {
        self.hold.as_deref()
    }

    /// Record one complete check: the problems it found (none = all invariants hold).
    pub fn observe(&mut self, problems: &[Problem]) -> Option<Change> {
        if problems.is_empty() {
            self.streak = 0;
            return self.hold.take().map(|_| Change::Cleared);
        }
        self.streak = self.streak.saturating_add(1);
        let why = problems.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
        if self.streak < Self::REQUIRED_STREAK {
            return None;
        }
        let tripped = self.hold.is_none();
        self.hold = Some(why.clone());
        tripped.then_some(Change::Tripped(why))
    }
}

/// Reading the figures: each wBDX contract over its chain's RPC, and consensus over this
/// signer's own daemon. Every signer reads its own; nothing here is taken from a peer.
#[cfg(feature = "evm-watcher")]
pub mod read {
    use super::{ChainFigures, NativeFigures};
    use crate::evm_watcher::JsonRpcClient;
    use serde_json::{json, Value};

    const TOTAL_SUPPLY: &str = "0x18160ddd";
    const WINDOW_MINT_CAP: &str = "0x466351f2";
    const PER_TX_MAX: &str = "0x89fbcc98";
    const BOND_BACKING_CAP_LIMIT: &str = "0x8e801d1b";
    const NATIVE_RELEASE_MAX: &str = "0xbd0b3279";
    const DECIMALS: &str = "0x313ce567";

    fn word<C: JsonRpcClient>(client: &C, contract: &[u8; 20], selector: &str, what: &str) -> Result<u128, String> {
        let to: String = contract.iter().map(|b| format!("{b:02x}")).collect();
        let raw = client
            .call("eth_call", json!([{ "to": format!("0x{to}"), "data": selector }, "latest"]))
            .map_err(|e| format!("{what}(): {e:?}"))?;
        let hex = raw
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| format!("{what}(): not a 32-byte word: {raw}"))?;
        let (high, low) = hex.split_at(32);
        if high.bytes().any(|c| c != b'0') {
            return Err(format!("{what}(): {hex} does not fit 128 bits"));
        }
        u128::from_str_radix(low, 16).map_err(|e| format!("{what}(): {e}"))
    }

    /// A wBDX contract's supply, caps and units.
    pub fn chain_figures<C: JsonRpcClient>(client: &C, chain_id: u64, contract: &[u8; 20]) -> Result<ChainFigures, String> {
        let r = |sel: &str, what: &str| word(client, contract, sel, what).map_err(|e| format!("chain {chain_id}: {e}"));
        let decimals = r(DECIMALS, "decimals")?;
        Ok(ChainFigures {
            chain_id,
            total_supply: r(TOTAL_SUPPLY, "totalSupply")?,
            window_mint_cap: r(WINDOW_MINT_CAP, "windowMintCap")?,
            per_tx_max: r(PER_TX_MAX, "perTxMax")?,
            bond_backing_cap_limit: r(BOND_BACKING_CAP_LIMIT, "bondBackingCapLimit")?,
            native_release_max: r(NATIVE_RELEASE_MAX, "NATIVE_RELEASE_MAX")?,
            decimals: u8::try_from(decimals).map_err(|_| format!("chain {chain_id}: decimals() = {decimals}"))?,
        })
    }

    /// The gateway's balance and consensus's backing and release maximum.
    pub fn native_figures<C: JsonRpcClient>(daemon: &C, gateway_id: &str) -> Result<NativeFigures, String> {
        let v = daemon
            .call("bridge_get_reserves", json!({ "gateway_id": gateway_id }))
            .map_err(|e| format!("bridge_get_reserves: {e:?}"))?;
        parse_reserves(&v)
    }

    /// Parse a `bridge_get_reserves` result. A gateway that is not registered, or a
    /// daemon too old to report `slashable_backing`, is an error, never a zero.
    pub fn parse_reserves(v: &Value) -> Result<NativeFigures, String> {
        if v.get("registered").and_then(Value::as_bool) != Some(true) {
            return Err("bridge_get_reserves: the gateway is not registered".into());
        }
        let num = |f: &str| {
            v.get(f).and_then(Value::as_u64).map(u128::from).ok_or_else(|| {
                format!("bridge_get_reserves: no `{f}` in the reply (a daemon from before the solvency check?)")
            })
        };
        Ok(NativeFigures {
            gateway_balance: num("gateway_balance")?,
            slashable_backing: num("slashable_backing")?,
            native_per_tx_max: num("per_tx_max")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BDX: u128 = 1_000_000_000;

    fn chain(id: u64, supply: u128) -> ChainFigures {
        ChainFigures {
            chain_id: id,
            total_supply: supply,
            window_mint_cap: 10_000 * BDX,
            per_tx_max: 1_000 * BDX,
            bond_backing_cap_limit: 100_000 * BDX,
            native_release_max: 50_000 * BDX,
            decimals: 9,
        }
    }
    fn configured(id: u64) -> ConfiguredCaps {
        ConfiguredCaps { chain_id: id, per_tx_max: 1_000 * BDX, per_epoch_cap: 10_000 * BDX }
    }
    /// The devnet: threshold 4 of 100,000 BDX bonds.
    fn native(balance: u128) -> NativeFigures {
        NativeFigures { gateway_balance: balance, slashable_backing: 400_000 * BDX, native_per_tx_max: 50_000 * BDX }
    }

    #[test]
    fn supply_up_to_the_reserve_is_solvent_and_one_unit_more_is_not() {
        let n = native(80 * BDX);
        assert_eq!(check_solvency(&[chain(1, 50 * BDX), chain(2, 30 * BDX)], &n), None, "exactly backed");
        assert_eq!(check_solvency(&[chain(1, 50 * BDX), chain(2, 10 * BDX)], &n), None, "in flight");
        assert_eq!(
            check_solvency(&[chain(1, 50 * BDX), chain(2, 30 * BDX + 1)], &n),
            Some(Problem::Insolvent { supply: 80 * BDX + 1, reserve: 80 * BDX }),
            "summed across chains"
        );
        let shown = Problem::Insolvent { supply: 80 * BDX + 1, reserve: 80 * BDX }.to_string();
        assert!(shown.contains("short by 1"), "{shown}");
    }

    #[test]
    fn a_consistent_configuration_has_no_problems() {
        assert!(check_configuration(&[configured(1)], &[chain(1, 0)], &native(0)).is_empty());
    }

    #[test]
    fn caps_are_summed_across_chains_against_the_bond() {
        // Each chain's own contract is satisfied (window cap <= its backing / 2) ...
        let mut chains: Vec<ChainFigures> = (1..=4).map(|i| chain(i, 0)).collect();
        let cfg: Vec<ConfiguredCaps> = (1..=4).map(configured).collect();
        assert!(check_configuration(&cfg, &chains, &native(0)).is_empty(), "4 x 100k claimed = 400k bonded");
        // ... but a fifth chain claims backing that is already spoken for.
        chains.push(chain(5, 0));
        let p = check_configuration(&cfg, &chains, &native(0));
        assert_eq!(p, vec![Problem::ClaimedBackingAboveBond { claimed: 500_000 * BDX, backing: 400_000 * BDX }]);
        // And caps large enough that two windows everywhere outrun the bond.
        for c in &mut chains {
            c.window_mint_cap = 50_000 * BDX;
            c.bond_backing_cap_limit = 0;
        }
        let p = check_configuration(&cfg, &chains, &native(0));
        assert!(p.contains(&Problem::BurstAboveBacking { exposure: 500_000 * BDX, backing: 400_000 * BDX }), "{p:?}");
    }

    #[test]
    fn signer_contract_and_consensus_must_agree() {
        let mut c = chain(1, 0);
        c.decimals = 18;
        c.native_release_max = 60_000 * BDX;
        let cfg = ConfiguredCaps { chain_id: 1, per_tx_max: 2_000 * BDX, per_epoch_cap: 10_000 * BDX };
        let p = check_configuration(&[cfg, configured(7)], &[c], &native(0));
        assert_eq!(
            p,
            vec![
                Problem::WrongDecimals { chain_id: 1, decimals: 18 },
                Problem::CapMismatch {
                    chain_id: 1,
                    configured: (2_000 * BDX, 10_000 * BDX),
                    contract: (1_000 * BDX, 10_000 * BDX)
                },
                Problem::NativeMaxMismatch { chain_id: 1, contract: 60_000 * BDX, native: 50_000 * BDX },
                Problem::MissingChain(7),
            ]
        );
    }

    #[test]
    fn the_guard_holds_on_a_repeated_problem_and_releases_on_a_clean_check() {
        let bad = [Problem::Insolvent { supply: 2, reserve: 1 }];
        let mut g = SolvencyGuard::new();
        assert_eq!(g.observe(&bad), None, "one reading may be a race");
        assert_eq!(g.hold(), None);
        assert_eq!(g.observe(&[]), None, "the race resolved: nothing happened");
        assert_eq!(g.observe(&bad), None);
        assert!(matches!(g.observe(&bad), Some(Change::Tripped(why)) if why.contains("exceeds")));
        assert!(g.hold().is_some());
        assert_eq!(g.observe(&bad), None, "already held: no second trip");
        assert_eq!(g.observe(&[]), Some(Change::Cleared));
        assert_eq!(g.hold(), None);
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn reserves_reply_is_parsed_and_gaps_are_errors() {
        use serde_json::json;
        let ok = json!({"registered": true, "gateway_balance": 30_000_000_000u64,
                        "slashable_backing": 400_000_000_000_000u64, "per_tx_max": 50_000_000_000_000u64});
        assert_eq!(
            read::parse_reserves(&ok).unwrap(),
            NativeFigures { gateway_balance: 30 * BDX, slashable_backing: 400_000 * BDX, native_per_tx_max: 50_000 * BDX }
        );
        let old = json!({"registered": true, "gateway_balance": 1u64, "per_tx_max": 1u64});
        assert!(read::parse_reserves(&old).unwrap_err().contains("slashable_backing"));
        let gone = json!({"registered": false, "gateway_balance": 0u64});
        assert!(read::parse_reserves(&gone).unwrap_err().contains("not registered"));
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn contract_figures_are_read_by_selector() {
        use crate::evm_watcher::{JsonRpcClient, RpcError};
        use serde_json::{json, Value};
        struct Fake;
        impl JsonRpcClient for Fake {
            fn call(&self, _m: &str, p: Value) -> Result<Value, RpcError> {
                let v: u128 = match p[0]["data"].as_str().unwrap() {
                    "0x18160ddd" => 7,
                    "0x466351f2" => 10,
                    "0x89fbcc98" => 1,
                    "0x8e801d1b" => 20,
                    "0xbd0b3279" => 50,
                    "0x313ce567" => 9,
                    other => panic!("unexpected selector {other}"),
                };
                Ok(json!(format!("0x{v:064x}")))
            }
        }
        let f = read::chain_figures(&Fake, 31337, &[0; 20]).unwrap();
        assert_eq!(
            f,
            ChainFigures {
                chain_id: 31337,
                total_supply: 7,
                window_mint_cap: 10,
                per_tx_max: 1,
                bond_backing_cap_limit: 20,
                native_release_max: 50,
                decimals: 9
            }
        );
    }
}

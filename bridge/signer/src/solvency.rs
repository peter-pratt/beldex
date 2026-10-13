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
//! And it signs only for contract code it has pinned (M-05). wBDX sits behind a UUPS
//! proxy: an upgrade changes what a mint signature authorises without changing the address
//! the signer talks to. The proxy's EIP-1967 implementation slot, and the hash of the code
//! there, must match the operator's pin; a signer without a pin does not start, and one
//! whose contract is upgraded under it stops signing until its operator has reviewed the
//! new code and pinned it.
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

/// The contract code a signer has verified and agreed to sign for: the address the proxy's
/// EIP-1967 implementation slot holds, and the keccak256 of that address's runtime code.
///
/// A signature authorises whatever the code behind the proxy does with it. An upgrade
/// changes that without changing the proxy's address, so the signer pins the code itself
/// and stops signing when it changes, until its operator has looked at the new code and
/// pinned it. The address alone would do while code at an address cannot change; the hash
/// is kept as well so a pin states exactly which code was reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImplementationPin {
    pub address: [u8; 20],
    pub code_hash: [u8; 32],
}

/// One wBDX contract's figures, read from its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFigures {
    pub chain_id: u64,
    /// What the proxy points at now.
    pub implementation: ImplementationPin,
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
    /// The implementation this signer agreed to sign for.
    pub implementation: Option<ImplementationPin>,
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
    /// No implementation pinned for a chain: the signer would sign for whatever code is
    /// behind the proxy.
    ImplementationUnpinned { chain_id: u64, found: ImplementationPin },
    /// The proxy points at code other than the pinned implementation: it was upgraded.
    ImplementationChanged { chain_id: u64, pinned: ImplementationPin, found: ImplementationPin },
}

impl Problem {
    /// Whether one reading can show this problem without it being real. Only a shortfall
    /// can: a mint may land between reading the balance and reading the supply. Everything
    /// else is read from settled state, and a hold on it should not wait for a second look.
    pub fn may_be_a_race(&self) -> bool {
        matches!(self, Problem::Insolvent { .. })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl fmt::Display for ImplementationPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "implementation 0x{} code hash 0x{}", hex(&self.address), hex(&self.code_hash))
    }
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
            Problem::ImplementationUnpinned { chain_id, found } => write!(
                f,
                "chain {chain_id}: no implementation pinned. The proxy points at {found}; review that code, \
                 then set \"implementation\": \"0x{}\", \"implementation_codehash\": \"0x{}\" for this chain",
                hex(&found.address),
                hex(&found.code_hash)
            ),
            Problem::ImplementationChanged { chain_id, pinned, found } => write!(
                f,
                "chain {chain_id}: the wBDX proxy does not run the pinned code (it was upgraded, or the pin is \
                 wrong): pinned {pinned}, found {found}. No signing until that code is reviewed and pinned"
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
        match c.implementation {
            None => problems.push(Problem::ImplementationUnpinned { chain_id: f.chain_id, found: f.implementation }),
            Some(pinned) if pinned != f.implementation => problems.push(Problem::ImplementationChanged {
                chain_id: f.chain_id,
                pinned,
                found: f.implementation,
            }),
            Some(_) => {}
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
/// so one failed solvency check is not proof; [`Self::REQUIRED_STREAK`] in a row are. Any
/// other problem (an upgraded implementation, caps that disagree) is read from settled
/// state and holds at once. A check that
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
        if self.streak < Self::REQUIRED_STREAK && problems.iter().all(Problem::may_be_a_race) {
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
    use super::{ChainFigures, ImplementationPin, NativeFigures};
    use crate::evm_watcher::JsonRpcClient;
    use serde_json::{json, Value};

    const TOTAL_SUPPLY: &str = "0x18160ddd";
    const WINDOW_MINT_CAP: &str = "0x466351f2";
    const PER_TX_MAX: &str = "0x89fbcc98";
    const BOND_BACKING_CAP_LIMIT: &str = "0x8e801d1b";
    const NATIVE_RELEASE_MAX: &str = "0xbd0b3279";
    const DECIMALS: &str = "0x313ce567";
    /// EIP-1967: `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`.
    pub const IMPLEMENTATION_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

    fn hex_bytes(v: &Value, what: &str) -> Result<Vec<u8>, String> {
        let s = v.as_str().and_then(|s| s.strip_prefix("0x")).ok_or_else(|| format!("{what}: not hex: {v}"))?;
        if s.len() % 2 != 0 {
            return Err(format!("{what}: odd-length hex"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("{what}: {e}")))
            .collect()
    }

    /// What the proxy at `contract` runs: the address in its EIP-1967 implementation slot,
    /// and the keccak256 of the runtime code there.
    pub fn implementation<C: JsonRpcClient>(client: &C, contract: &[u8; 20]) -> Result<ImplementationPin, String> {
        use sha3::{Digest, Keccak256};
        let to: String = contract.iter().map(|b| format!("{b:02x}")).collect();
        let slot = client
            .call("eth_getStorageAt", json!([format!("0x{to}"), IMPLEMENTATION_SLOT, "latest"]))
            .map_err(|e| format!("implementation slot: {e:?}"))?;
        let word = hex_bytes(&slot, "implementation slot")?;
        if word.len() != 32 || word[..12].iter().any(|b| *b != 0) {
            return Err(format!("implementation slot: not an address: {slot}"));
        }
        let address: [u8; 20] = word[12..].try_into().expect("length checked");
        if address == [0; 20] {
            return Err("implementation slot is empty: not an EIP-1967 proxy".into());
        }
        let impl_hex: String = address.iter().map(|b| format!("{b:02x}")).collect();
        let code = client
            .call("eth_getCode", json!([format!("0x{impl_hex}"), "latest"]))
            .map_err(|e| format!("implementation code: {e:?}"))?;
        let code = hex_bytes(&code, "implementation code")?;
        if code.is_empty() {
            return Err(format!("no code at the implementation 0x{impl_hex}"));
        }
        Ok(ImplementationPin { address, code_hash: Keccak256::digest(&code).into() })
    }

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
            implementation: implementation(client, contract).map_err(|e| format!("chain {chain_id}: {e}"))?,
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
    const PIN: ImplementationPin = ImplementationPin { address: [0xA1; 20], code_hash: [0xC0; 32] };

    fn chain(id: u64, supply: u128) -> ChainFigures {
        ChainFigures {
            chain_id: id,
            implementation: PIN,
            total_supply: supply,
            window_mint_cap: 10_000 * BDX,
            per_tx_max: 1_000 * BDX,
            bond_backing_cap_limit: 100_000 * BDX,
            native_release_max: 50_000 * BDX,
            decimals: 9,
        }
    }
    fn configured(id: u64) -> ConfiguredCaps {
        ConfiguredCaps { chain_id: id, per_tx_max: 1_000 * BDX, per_epoch_cap: 10_000 * BDX, implementation: Some(PIN) }
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
        let cfg = ConfiguredCaps { chain_id: 1, per_tx_max: 2_000 * BDX, per_epoch_cap: 10_000 * BDX, implementation: Some(PIN) };
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
    fn a_signer_signs_only_for_the_implementation_it_pinned() {
        let n = native(0);
        let mut unpinned = configured(1);
        unpinned.implementation = None;
        let p = check_configuration(&[unpinned], &[chain(1, 0)], &n);
        assert_eq!(p, vec![Problem::ImplementationUnpinned { chain_id: 1, found: PIN }]);
        let shown = p[0].to_string();
        assert!(
            shown.contains(&format!("\"implementation\": \"0x{}\"", "a1".repeat(20)))
                && shown.contains(&format!("\"implementation_codehash\": \"0x{}\"", "c0".repeat(32))),
            "the refusal says what to pin once the code is reviewed: {shown}"
        );

        // Upgraded under the signer: new address, or same address with other code.
        for found in [
            ImplementationPin { address: [0xB2; 20], ..PIN },
            ImplementationPin { code_hash: [0xC1; 32], ..PIN },
        ] {
            let mut upgraded = chain(1, 0);
            upgraded.implementation = found;
            let p = check_configuration(&[configured(1)], &[upgraded], &n);
            assert_eq!(p, vec![Problem::ImplementationChanged { chain_id: 1, pinned: PIN, found }]);
        }
    }

    #[test]
    fn an_upgrade_holds_signing_on_the_first_check() {
        let upgraded = Problem::ImplementationChanged {
            chain_id: 1,
            pinned: PIN,
            found: ImplementationPin { address: [0xB2; 20], ..PIN },
        };
        assert!(!upgraded.may_be_a_race());
        let mut g = SolvencyGuard::new();
        assert!(matches!(g.observe(std::slice::from_ref(&upgraded)), Some(Change::Tripped(why)) if why.contains("does not run the pinned code")));
        // A shortfall alongside it does not soften that.
        let mut g = SolvencyGuard::new();
        assert!(g.observe(&[Problem::Insolvent { supply: 2, reserve: 1 }, upgraded]).is_some());
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
        use sha3::{Digest, Keccak256};
        const CODE: &str = "0x6080604052";
        struct Fake;
        impl JsonRpcClient for Fake {
            fn call(&self, m: &str, p: Value) -> Result<Value, RpcError> {
                match m {
                    "eth_getStorageAt" => {
                        assert_eq!(p[1], read::IMPLEMENTATION_SLOT);
                        return Ok(json!(format!("0x{}{}", "00".repeat(12), "a1".repeat(20))));
                    }
                    "eth_getCode" => {
                        assert_eq!(p[0], format!("0x{}", "a1".repeat(20)), "the code is read at the implementation");
                        return Ok(json!(CODE));
                    }
                    _ => {}
                }
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
                implementation: ImplementationPin {
                    address: [0xA1; 20],
                    code_hash: Keccak256::digest([0x60, 0x80, 0x60, 0x40, 0x52]).into(),
                },
                total_supply: 7,
                window_mint_cap: 10,
                per_tx_max: 1,
                bond_backing_cap_limit: 20,
                native_release_max: 50,
                decimals: 9
            }
        );
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn a_contract_that_is_not_a_proxy_is_refused() {
        use crate::evm_watcher::{JsonRpcClient, RpcError};
        use serde_json::{json, Value};
        struct NoProxy;
        impl JsonRpcClient for NoProxy {
            fn call(&self, _m: &str, _p: Value) -> Result<Value, RpcError> {
                Ok(json!(format!("0x{}", "00".repeat(32))))
            }
        }
        assert!(read::implementation(&NoProxy, &[1; 20]).unwrap_err().contains("not an EIP-1967 proxy"));
    }
}

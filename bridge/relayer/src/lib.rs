//! # Beldex Sovereign Bridge — keyless relayer (**Phase I**)
//!
//! A relayer is a **permissionless, keyless courier**: it carries an already-committee-signed
//! wBDX payload to its destination EVM chain and pays gas to broadcast it. It holds **no
//! bridge key** and forges nothing — the authorizing signature is complete before a relayer
//! touches it, and the wBDX contract verifies it on-chain. Relayers are therefore **never a
//! trust component** (whitepaper §3.1): if every relayer disappears, any user builds the same
//! transaction from the signed payload and submits it themselves, so the bridge is never
//! liveness-blocked on relayers.
//!
//! ## What this crate provides
//!   * [`abi`] — byte-exact ABI calldata for the two signed wBDX calls a relayer carries,
//!     `mint(...)` and `rotateSigner(...)` (selectors + encoding pinned against
//!     `bridge-contract/src/WrappedBDX.sol`).
//!   * [`payload`] — [`payload::RelayPayload`], a self-contained signed payload, its JSON
//!     codec (the signer→relayer / user→relayer handoff), and [`payload::PreparedCall`], the
//!     exact `{chain_id, to, data}` to broadcast (or hand to `cast send` / a wallet).
//!   * [`submit`] — the [`submit::TxSubmitter`] broadcast seam + a mock.
//!   * [`rlp`] + [`eip1559`] — a minimal RLP encoder and type-2 transaction construction
//!     (sighash + signed envelope), both pure and tested.
//!   * [`http_submit`] (feature `submit-http`) — the **reference gas-paying service**:
//!     resolve nonce/fees/gas, sign the outer envelope with a funded key, broadcast. The gas
//!     key carries **no bridge authority** (the committee signature is inside the calldata),
//!     so a leak costs gas, never funds.
//!
//! The **submit-your-own** liveness guarantee is delivered today by
//! [`payload::RelayPayload::to_prepared`]: no key, no service, no trust — just the calldata.

pub mod abi;
pub mod digest;
pub mod eip1559;
pub mod payload;
pub mod rlp;
pub mod submit;

#[cfg(feature = "submit-http")]
pub mod http_submit;

pub use digest::{mint_digest, mint_preimage};
pub use eip1559::Eip1559Tx;
pub use payload::{PreparedCall, RelayPayload};
pub use submit::{SubmitError, TxSubmitter};

#[cfg(feature = "submit-http")]
pub use http_submit::{ChainEndpoint, HttpSubmitter};

/// Crate version.
pub const RELAYER_VERSION: [u16; 3] = [0, 1, 0];

/// A shared HTTP agent with bounded timeouts.
///
/// `ureq` applies no read timeout by default, so an endpoint that accepts the
/// connection and then never answers stalls the submitter indefinitely — with a
/// signed transaction in hand and no way to know whether it landed.
///
/// Overridable per deployment:
///   * `BRIDGE_RELAYER_HTTP_CONNECT_SECS` (default 5)
///   * `BRIDGE_RELAYER_HTTP_READ_SECS`    (default 20)
///   * `BRIDGE_RELAYER_HTTP_TOTAL_SECS`   (default 30)
#[cfg(feature = "submit-http")]
pub fn http_agent() -> ureq::Agent {
    fn secs(var: &str, default: u64) -> std::time::Duration {
        let v = std::env::var(var).ok().and_then(|s| s.trim().parse::<u64>().ok());
        std::time::Duration::from_secs(v.filter(|n| *n > 0).unwrap_or(default))
    }
    ureq::AgentBuilder::new()
        .timeout_connect(secs("BRIDGE_RELAYER_HTTP_CONNECT_SECS", 5))
        .timeout_read(secs("BRIDGE_RELAYER_HTTP_READ_SECS", 20))
        .timeout(secs("BRIDGE_RELAYER_HTTP_TOTAL_SECS", 30))
        .build()
}

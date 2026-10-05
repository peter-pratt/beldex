# beldex-bridge-relayer (Phase I)

A **permissionless, keyless courier** for the Beldex Sovereign Bridge. It carries an
already-committee-signed wBDX payload to its destination EVM chain and pays gas to broadcast
it. It holds **no bridge key** and forges nothing — the authorizing signature is complete
before the relayer touches it, and the wBDX contract verifies it on-chain. Relayers are
therefore **never a trust component** (whitepaper §3.1): if every relayer disappears, any
user builds the same transaction from the signed payload and submits it themselves.

## What's here

```
src/abi.rs      byte-exact ABI calldata for mint(...) / rotateSigner(...) (selectors pinned)
src/payload.rs  RelayPayload (self-contained signed payload) + JSON codec + PreparedCall
src/submit.rs   TxSubmitter broadcast seam + a mock
src/http_submit.rs  the gas-paying submitter behind `relay` (feature submit-http)
src/relay_state.rs  per-wallet in-flight transactions, locked on disk (feature submit-http)
src/main.rs     `prepare` — emit the {chain_id, to, data} to broadcast; `relay` — broadcast it
```

## Build & test

Standalone crate (like `bridge/signer/`):

```bash
cd bridge/relayer
cargo test
```

## Submit-your-own (the liveness guarantee)

`prepare` reads a signed payload and prints the exact call to broadcast — no bridge key, no
running service:

```bash
beldex-bridge-relayer prepare payload.json
# chain_id: 1
# to:       0x<wbdx contract>
# data:     0x96d66de0...        # mint(to, amount, beldexTxid, sig) calldata

# broadcast with any wallet / tooling, paying your own gas:
cast send 0x<contract> 0x<data> --rpc-url <chain rpc> --private-key <your gas key>
```

Payload JSON (produced by a signer, or hand-assembled):

```json
{ "kind": "mint", "contract": "<40hex>", "chain_id": 1, "to": "<40hex>",
  "amount": "1000", "beldex_txid": "<64hex>", "sig": "<130hex r‖s‖v>" }

{ "kind": "rotate", "contract": "<40hex>", "chain_id": 1,
  "new_signer": "<40hex>", "new_key_epoch": 7, "sig": "<130hex>" }
```

## Reference relayer (`relay`, feature `submit-http`)

`relay` builds the outer EIP-1559 transaction around a signed payload, signs it with a funded
gas key (no bridge authority: a leak costs gas, never funds) and broadcasts it. A call that
would revert (already minted, over cap, bad signature) fails gas estimation and is reported
without spending anything.

```bash
cargo build --features submit-http
export RELAYER_GAS_KEY=<32-byte hex>
export RELAYER_CHAINS='[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545"}]'
export RELAYER_STATE_DIR=/var/lib/beldex-relayer   # default ./relayer-state
beldex-bridge-relayer relay payload.json           # or `relay -` for stdin
```

Each gas wallet's in-flight transactions are kept in `RELAYER_STATE_DIR`, one file per
`(chain, wallet)`, and every run holds an exclusive lock on it while deciding. With that:

- a payload whose call is already pending from this wallet is not sent again (`already
  pending`), so a re-delivered mint does not pay for a second, reverting transaction;
- a transaction still unmined after 3 minutes is re-signed at the same nonce with at least
  +25% fees, or the chain's current fees if higher, up to `max_fee_cap_wei`, so a fee spike
  cannot leave it blocking every later transaction;
- one whose call would now revert (another relayer minted the deposit) is replaced by a
  zero-value transfer to the wallet itself, freeing the nonce without paying for a revert;
- concurrent runs on one key take turns instead of picking the same nonce.

Stale transactions are only looked at when `relay` runs. Signers re-deliver unminted payloads
every few minutes, so while anything is outstanding that happens on its own. **Every relay on
one gas key must use the same state directory**; two directories for one key reintroduce
nonce collisions.

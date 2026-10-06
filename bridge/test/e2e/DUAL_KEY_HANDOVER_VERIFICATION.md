# Dual-key committee hand-over, verified end to end on a devnet

**Date:** 2026-10-06 · **Result:** ✅ Two consecutive committee rotations, the first with a
membership change (one operator leaving, one joining), each moving **both** bridge keys:
the wBDX mint key (`Pevm`) and the gateway owner key (`Pgw`). In each one the retired keys
are refused on both chains and the new ones are accepted. Rotation acknowledgements were
submitted automatically. The leaving operator's bond was released after exactly the second
hand-over, not the first. A crash in the middle of the on-chain step was resumed cleanly.

This replaces the earlier record (`bridge/docs/H6_ROTATION_DEVNET_VERIFICATION.md`, a
`Pevm`-only rotation on the V1 contract) as evidence for the full hand-over.

## Setup

- 7 master nodes, each a bonded bridge seat with its own operator wallet; the committee is
  6 of them, threshold 4. One plain node. anvil for the EVM side, chain id 31337.
- Built from `security-hardening` at the rotation-ack commit (`6d1748d35`) plus this run's
  tooling fixes; `bridge-contract` at `a417a14`.
- The signers ran live (`serve-live.sh`) throughout, with a funded wallet RPC paying for
  rotation acks (`ACK_WALLET_RPC`) and a relayer for mints.

```bash
cd utils/local-devnet
DEVNET_MNS=7 DEVNET_BRIDGE_SEATS=7 python3 master_node_network.py --fresh   # leave running
BC=<bridge-contract checkout> ./bootstrap-bridge.sh                          # DKG gen 0, deploy, gateway
GATEWAY_ID=… VIEW_SECRET=… WBDX=… ACK_WALLET_RPC=http://127.0.0.1:<wallet>/json_rpc \
  RELAY_CMD='env RELAYER_GAS_KEY=… RELAYER_CHAINS=… RELAYER_STATE_DIR=… beldex-bridge-relayer relay -' \
  RELAY_NODES=0 ./serve-live.sh
# each rotation, while the old committee keeps serving on the default ports:
CEREMONY_YES=1 MESH_PORT_BASE=7000 BRIDGE_DIR=<bridge-contract checkout> ./rotate-ceremony.sh
# then restart serve-live.sh so the nodes serve the promoted shares
```

## What happened, in order

| # | Action | Observed |
|---|---|---|
| 1 | Bootstrap: generation 0 dual DKG, wBDX deployed, gateway registered (owner = Pgw) | contract emits `Rotated(…, 1)`; signers ack it; L1 binds chain 31337 to contract `0xe7f1…0512`, observed key epoch 1 |
| 2 | Operator Op7 (on the committee) asks to leave at height 395 | baseline `{31337: 2, gateway: 1}` (two hand-overs on each side), unlock height 755 |
| 3 | Next bridge epoch | committee recomputed without Op7, with the 7th seat in its place |
| 4 | Rotation 1 (`rotate-ceremony.sh`), DKG generation 1 among the NEW membership; the OLD membership, Op7 included, signs the hand-over | successor `0xc9aa…977a`; contract at epoch 2; gateway owner moved; new key mints, retired key does not |
| 5 | Old signers | log `KEY REPLACED` for the wBDX signer and the gateway owner and stop opening work for them |
| 6 | Acks | epoch-2 ack submitted automatically; L1 observed `{31337: 2, gateway: 1}` |
| 7 | Op7's bond, height ≫ 755 | **still locked**: one hand-over on each side is not past its baseline |
| 8 | Live service restarted on generation 1 | the joiner (committee index 1) signs; 40 BDX deposit minted, 15 wBDX burn released |
| 9 | Rotation 2, killed (`kill -9`) during step 5, the on-chain propose/activate | — |
| 10 | `rotate-ceremony.sh --from 6` | detects the rotation already live on chain, verifies it, hands the gateway over, archives `shares-gen1`, proves the hand-off with the generation-1 key as the retired one |
| 11 | Acks | L1 observed `{31337: 3, gateway: 2}` |
| 12 | Op7's bond | **released**: seat cleared, 100,000 BDX spendable in Op7's wallet |
| 13 | Live service on generation 2 | 9 BDX deposit minted; 3 wBDX burn released, mined at height 1475 |

An earlier same-membership rotation on a 6-node devnet also covered the hand-over gap:
a deposit and a burn made after the old committee stopped and before the new one started
were both paid out by the new committee (mint seen on anvil; release mined at height
1047). A withdrawal from the gateway threshold-signed with the archived generation-0 shares
was refused by the daemon: `signature does not verify against the gateway owner key`.

## Both keys, both directions

| | retired key | new key |
|---|---|---|
| mint (wBDX contract) | refused (`06-handoff-proof.sh`, every rotation) | accepted (live mints after each restart) |
| release (Beldex gateway) | refused (`gateway_submit_transfer` with generation-0 shares) | accepted (releases mined at 1047 and 1475) |

## Defects found and fixed by this run

- **The old committee could not keep serving during a rotation on one host.** Every
  script used mesh port base 6000, the same ports as the live signers, so a DKG or signing
  run for the ceremony collided with them. The scripts now take `MESH_PORT_BASE`.
- **The ceremony's state leaked between rotations.** `.ceremony/state` was never reset, so
  a resumed second rotation that skipped step 7 would have read the first rotation's
  `ARCHIVE` and made step 8 sign "as the retired committee" with a key retired one
  rotation earlier, passing with the wrong key. A fresh run now sets the old state aside.
- **The devnet could not test a membership change.** With 6 seats and an activation floor
  of 6, any operator leaving deactivated the bridge. `DEVNET_MNS` / `DEVNET_BRIDGE_SEATS`
  now allow a queued seat.

## Limits of this evidence

- Finality: anvil has none, so the EVM side ran with `depth_only_finality`, and the
  devnet never checkpoints, so deposits settled on `BRIDGE_SIGNER_BELDEX_CONFIRMATIONS`.
  Both are test-network modes the production configuration refuses.
- One host, one user, plaintext mesh (no CURVE): threshold independence is not tested.
- The governance re-point of the gateway (checkpoint-quorum evidence) was not exercised;
  the hand-over used the owner-signed descriptor update, which is the normal path.
- All signers shared one wallet for acks, so five of six submissions per ack were refused
  as double spends of the same coins. With a wallet per operator the mempool keeps one
  ack per (chain, key epoch) and the rest are refused without a fee.

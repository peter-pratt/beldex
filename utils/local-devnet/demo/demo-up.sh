#!/usr/bin/env bash
# demo-up.sh — bring up the whole bridge demo on a FRESH devnet, unattended.
#
#     ./demo/demo-up.sh
#
# In order: stop anything left from an earlier run, start anvil, start the devnet harness
# (SEATS master nodes, each with a bridge seat), fund the demo wallets, run the bridge
# bootstrap (first DKG, wBDX deploy, gateway, signers, miner), start the relayer, the
# hand-over submitter and the standby signers. After this the bridge runs on its own, inside
# the signers: each epoch's committee makes its key (dkg-auto), attests it on chain, and the
# outgoing committee hands wBDX and the gateway over to it; a standby key is made, named and
# kept proven, and takes over if the live key's holders vanish. The only things left to
# people are the user's transfers and an operator's leave request — see demo/README in the
# guide, or the helper scripts next to this one.
#
# Env:
#   SEATS      master nodes, each a bridge seat   (default 11, at most 11; committee is 6, threshold 4)
#   FORCE=1    start even if the memory check says it will not fit
#   BATCH      blocks per mining burst            (default 2)
#   INTERVAL   seconds between bursts             (default 15: 8 blocks/min, 15 min/epoch —
#              a DKG takes ~10-12 min on one laptop, so a rotation must fit in an epoch)
#   STANDBY=0  no standby signers              LAN=0  no Wi-Fi page / friend kit
#   ORCHESTRATOR=1  also run the old script-driven rotation (auto-rotate.sh); off by default,
#              the signers rotate by themselves
#
# Logs and demo state: utils/local-devnet/.demo/. Stop everything with ./demo/demo-down.sh.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
cd "$LOCAL"

SEATS="${SEATS:-11}"
export BATCH="${BATCH:-2}" INTERVAL="${INTERVAL:-15}"  # read by mine.sh loop
export ROTATE_TIMELOCK=120                            # devnet challenge window (01-deploy.sh)
export SIGNER="$SIGNER_BIN"                           # every devnet script honours SIGNER
export BRIDGE_SIGNER_DKG_TIMEOUT_SECS=1800             # dkg-init.sh / dkg-next.sh
export BC

# ── 0. preflight ─────────────────────────────────────────────────────────────
say "preflight"
# 12 master nodes is where the devnet switches from mined blocks to proof-of-stake blocks
# (11 validators + a leader, master_node_rules.h). Blocks then come every 30-60s whatever
# mine.sh does, so an epoch takes 1-2 hours instead of ~8 minutes.
[ "$SEATS" -le 11 ] || die "SEATS=$SEATS: at 12 or more master nodes the devnet produces proof-of-stake
   blocks (30-60s each) and an epoch takes 1-2 hours. Use SEATS=11 or fewer."
for b in "$BIN/beldexd" "$BIN/beldex-wallet-rpc" "$SIGNER_BIN" "$RELAYER_BIN"; do
  [ -x "$b" ] || die "missing $b — build it first"
done
for b in anvil cast forge; do command -v "$b" >/dev/null || die "missing $b (foundry)"; done
[ -x ./.venv/bin/python ] || die "missing utils/local-devnet/.venv (the harness's python)"
[ -d "$BC" ] || die "no bridge-contract checkout at $BC (set BC=…)"
# Roughly 300 MB per master node (daemon + operator wallet) plus ~2.5 GB for the signers,
# the extra DKG processes during a rotation, anvil and the relayer. Running out of memory
# here does not fail cleanly — the laptop swaps and freezes — so refuse up front.
AVAIL_MB=$(free -m | awk '/^Mem:/{print $7}')
NEED_MB=$(( SEATS * 300 + 2500 ))
if [ "$AVAIL_MB" -lt "$NEED_MB" ] && [ "${FORCE:-0}" != "1" ]; then
  die "$SEATS seats need about ${NEED_MB} MB free, only ${AVAIL_MB} MB is available.
   Close the browser / IDE / other heavy apps and retry, or use fewer seats
   (e.g. SEATS=16 ./demo/demo-up.sh). FORCE=1 skips this check."
fi
ok "binaries present, ${AVAIL_MB} MB available (about ${NEED_MB} MB needed for $SEATS seats)"
NEWER=$(find "$REPO/bridge/signer/src" "$REPO/bridge/signer/Cargo.toml" -newer "$SIGNER_BIN" -print -quit)
[ -z "$NEWER" ] || die "the signer binary $SIGNER_BIN is older than its source ($NEWER) — rebuild it first"
case "$SIGNER_BIN" in
  */release/*) ok "signer: release build" ;;
  *) warn "signer: DEBUG build — each DKG can take 5-20 min, longer than an 8-min epoch.
       Build the release one first:  (cd $REPO/bridge/signer && CARGO_BUILD_JOBS=3 cargo build --release --all-features)" ;;
esac

# ── 1. stop whatever is left from an earlier run ─────────────────────────────
say "stopping any earlier devnet / bridge processes"
"$DEMO_DIR/demo-down.sh" >/dev/null 2>&1 || true
rm -rf "$STATE_DIR" && mkdir -p "$STATE_DIR"
rm -rf "$LOCAL/.ceremony"                             # ceremony state belongs to the old chain
ok "clean"

# ── 2. anvil (a fresh EVM chain, so the contract is deployed for THIS devnet) ──
say "anvil"
# Reachable from the Wi-Fi (MetaMask on other laptops), and mining a block every 2s so a
# burn sent from MetaMask gets the confirmation the signers wait for without anyone mining.
nohup anvil --host 0.0.0.0 --port 8545 --chain-id 31337 --block-time 2 > "$STATE_DIR/anvil.log" 2>&1 &
for _ in $(seq 1 40); do cast chain-id --rpc-url "$EVM_RPC" >/dev/null 2>&1 && break; sleep 0.25; done
cast chain-id --rpc-url "$EVM_RPC" >/dev/null 2>&1 || die "anvil did not start; see $STATE_DIR/anvil.log"
ok "anvil on $EVM_RPC"

# ── 3. devnet harness ────────────────────────────────────────────────────────
# The harness keeps its daemons alive while it waits on stdin, so it is fed a pipe that
# never closes. It wipes testdata/ with --fresh, so its log lives in .demo/.
say "devnet harness: $SEATS master nodes, $SEATS bridge seats (takes a few minutes)"
DEVNET_MNS="$SEATS" DEVNET_BRIDGE_SEATS="$SEATS" \
  nohup bash -c 'sleep infinity | exec ./.venv/bin/python master_node_network.py --fresh' \
  > "$STATE_DIR/harness.log" 2>&1 &
echo $! > "$STATE_DIR/harness.pid"
for i in $(seq 1 360); do
  grep -q "Use Ctrl-C to exit" "$STATE_DIR/harness.log" 2>/dev/null && break
  if ! kill -0 "$(cat "$STATE_DIR/harness.pid")" 2>/dev/null; then
    tail -20 "$STATE_DIR/harness.log"; die "the harness exited; see $STATE_DIR/harness.log"
  fi
  [ $(( i % 12 )) -eq 0 ] && echo "   … still starting (height $(height || echo '?'))"
  sleep 5
done
grep -q "Use Ctrl-C to exit" "$STATE_DIR/harness.log" || die "harness not up after 30 min; see $STATE_DIR/harness.log"
ok "harness up at height $(height)"

# ── 4. demo wallets ──────────────────────────────────────────────────────────
say "funding the demo wallets from Mike"
ALICE_PORT=$(wallet_port Alice); BOB_PORT=$(wallet_port Bob); MIKE_PORT=$(wallet_port Mike)
ALICE_ADDR=$(wallet_address Alice); BOB_ADDR=$(wallet_address Bob)
# Block rewards go to Mike, never Alice: mine.sh otherwise picks the first funded wallet,
# and Alice's balance must change only through the demo's own deposits and releases.
export MINER_ADDR="$(wallet_address Mike)"
rpc_at "$MIKE_PORT" refresh >/dev/null
# Bob is the signers' fee wallet (attestations, acks, standby steps). Every one of those is
# its own transaction and change stays locked for a few blocks, so Bob gets many separate
# outputs: a standby round's members must all attest within its window. Mike's own change is
# locked after each payment too, so the payments are a dozen blocks apart. (16 outputs a tx at
# most, change included: Alice and 14 for Bob, then 15 for Bob.)
BOB15=$(for _ in $(seq 1 15); do printf ',{"address":"%s","amount":60000000000}' "$BOB_ADDR"; done)
FUND=$(rpc_at "$MIKE_PORT" transfer "{\"destinations\":[
          {\"address\":\"$ALICE_ADDR\",\"amount\":50000000000000}${BOB15#*\}}],\"priority\":1}")
echo "$FUND" | grep -q '"tx_hash"' || die "funding failed: $FUND"
./mine.sh 12 >/dev/null
# Mike's change unlocks once the wallet has seen enough blocks on top: refresh and retry.
for _ in 1 2 3 4 5 6; do
  rpc_at "$MIKE_PORT" refresh >/dev/null
  FUND=$(rpc_at "$MIKE_PORT" transfer "{\"destinations\":[${BOB15#,}],\"priority\":1}")
  echo "$FUND" | grep -q '"tx_hash"' && break
  ./mine.sh 4 >/dev/null
done
echo "$FUND" | grep -q '"tx_hash"' || die "funding Bob failed: $FUND"
./mine.sh 12 >/dev/null
ok "Alice (user, also funds friends) 50,000 BDX on wallet port $ALICE_PORT; Bob (signers' fee wallet) 30 x 60 BDX on $BOB_PORT"

# ── 5. bridge bootstrap: first DKG, wBDX, gateway, signers, miner ────────────
say "bridge bootstrap (first DKG, deploy, gateway, signers)"
# The signers' fee wallet (one per node in production; Bob for all of them here) pays their
# key attestations, rotation acks and standby steps. Supervised like systemd would: they
# follow every hand-over and takeover by themselves.
export ACK_WALLET_RPC="http://127.0.0.1:$BOB_PORT/json_rpc"
export SUPERVISE=1 RETIRE_AFTER_SECS=60
export HANDOVER_BUILDER="http://127.0.0.1:18090"                # the hand-over submitter, below
./bootstrap-bridge.sh 2>&1 | tee "$STATE_DIR/bootstrap.log" | grep -E '^== |WBDX=|GATEWAY_ADDR=|serving|!!' || true
grep -q "signer(s) serving" "$STATE_DIR/bootstrap.log" || die "bootstrap did not finish; see $STATE_DIR/bootstrap.log"
bridge_env
ok "bridge up: wBDX $WBDX, gateway $GATEWAY_ADDR"

# ── 6. relayer: broadcasts every signed mint to anvil ────────────────────────
say "relayer"
RELAY_SOCK="$(cd testdata && . ../sockbase.sh && sockbase_init >/dev/null 2>&1 && echo "$SOCKBASE/beldex-127.0.0.1-19191/devnet/beldexd.sock")"
# Two bus daemons, as the signers publish to both (serve-live.sh): one down is not the bus down.
BUS2_SOCK="${RELAY_SOCK%/beldex-127.0.0.1-19191/devnet/beldexd.sock}/beldex-127.0.0.1-19205/devnet/beldexd.sock"
BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$RELAY_SOCK,ipc://$BUS2_SOCK" \
BRIDGE_SIGNER_RELAY_CMD="$RELAYER_BIN relay -" \
RELAYER_GAS_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
RELAYER_STATE_DIR="$STATE_DIR/relayer-state" \
RELAYER_CHAINS='[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545"}]' \
  nohup "$SIGNER_BIN" relay-watch > "$STATE_DIR/relay-watch.log" 2>&1 &
echo $! > "$STATE_DIR/relay-watch.pid"
ok "relay-watch running (log .demo/relay-watch.log)"

# ── 6b. gateway hand-over submitter: Mike's wallet builds it, the signers sign it ──
say "gateway hand-over submitter"
HANDOVER_CHAINS="$( . testdata/serve-live.last
  printf '[{"chain_id":%s,"rpc":"%s","contract":"%s","confirmations":1,"per_epoch_cap":"%s","per_tx_max":"%s"}]' \
    "$CHAIN_ID" "$EVM_RPC" "$WBDX" "$WINDOW_MINT_CAP" "$PER_TX_MAX")"
BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$RELAY_SOCK,ipc://$BUS2_SOCK" \
BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
BRIDGE_SIGNER_HANDOVER_WALLET_RPC="http://127.0.0.1:$MIKE_PORT/json_rpc" \
BRIDGE_SIGNER_RELEASE_GATEWAY="$GATEWAY_ID" \
BRIDGE_SIGNER_EVM_CHAINS="$HANDOVER_CHAINS" \
BRIDGE_SIGNER_HANDOVER_LISTEN=127.0.0.1:18090 \
BRIDGE_SIGNER_STATUS_LISTEN=127.0.0.1:30090 BRIDGE_SIGNER_WALLET_LOW=10000000000 \
BRIDGE_SIGNER_HANDOVER_DIR="$STATE_DIR/handovers" \
  nohup "$SIGNER_BIN" handover-submit > "$STATE_DIR/handover-submit.log" 2>&1 &
echo $! > "$STATE_DIR/handover-submit.pid"
ok "handover-submit running (log .demo/handover-submit.log, records .demo/handovers)"

# ── 6c. standby signers: they make, attest, prove and, if needed, take over with a standby key
if [ "${STANDBY:-1}" = 1 ]; then
  say "standby signers"
  ( . testdata/serve-live.last
    ROLE=standby SHARE_SUBDIR=shares-standby MESH_PORT_BASE=7000 OUTAGE_WINDOW_SECS=60 \
      GATEWAY_ID="$GATEWAY_ID" VIEW_SECRET="$VIEW_SECRET" WBDX="$WBDX" \
      ./serve-live.sh ) > "$STATE_DIR/standby-start.log" 2>&1 \
    || { tail -5 "$STATE_DIR/standby-start.log"; die "standby signers did not start"; }
  ok "standby signers running (logs testdata/serve-standby-*.log)"
fi

# ── 7. Wi-Fi access for other laptops: node, bridge page, wallet kit ──────────
LAN_IP=127.0.0.1
if [ "${LAN:-1}" = 1 ]; then
say "access from the Wi-Fi"
LAN_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')
[ -n "$LAN_IP" ] || { warn "no LAN address found; other laptops cannot join"; LAN_IP=127.0.0.1; }
nohup python3 "$DEMO_DIR/lan-forward.py" 29191 19191 > "$STATE_DIR/lan-forward.log" 2>&1 &
echo $! > "$STATE_DIR/lan-forward.pid"
mkdir -p "$STATE_DIR/www"
cp "$DEMO_DIR/web/index.html" "$STATE_DIR/www/"
# MetaMask accepts a plain-http network only on localhost: the page always names
# 127.0.0.1:8545 — anvil itself here, the friend kit's evm-tunnel.sh on other laptops.
printf '{"wbdx":"%s","gateway":"%s","chainId":31337,"rpc":"http://127.0.0.1:8545"}\n' "$WBDX" "$GATEWAY_ADDR" \
  > "$STATE_DIR/www/config.json"
"$DEMO_DIR/friend-kit.sh" "$LAN_IP" 29191
nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory "$STATE_DIR/www" > "$STATE_DIR/web.log" 2>&1 &
echo $! > "$STATE_DIR/web.pid"
ok "bridge page http://$LAN_IP:8080   node $LAN_IP:29191   anvil http://$LAN_IP:8545"
fi

# ── 8. demo state + rotation orchestrator ────────────────────────────────────
H=$(height)
cat > "$STATE_DIR/demo.env" <<EOF
SEATS=$SEATS
ALICE_PORT=$ALICE_PORT
BOB_PORT=$BOB_PORT
MIKE_PORT=$MIKE_PORT
ALICE_ADDR=$ALICE_ADDR
LAN_IP=$LAN_IP
STARTED_HEIGHT=$H
EOF
# The committee whose key bootstrap installed, which can be one behind the tip by now: the
# orchestrator then rotates to the newer one straight away.
KEY_EPOCH=$(./dkg-next.sh --check shares | awk '{print $2}')
echo "${KEY_EPOCH:-$(( H / EPOCH_BLOCKS ))}" > "$STATE_DIR/last-rotated-epoch"
if [ "${ORCHESTRATOR:-0}" = 1 ]; then
  say "rotation orchestrator"
  nohup "$DEMO_DIR/auto-rotate.sh" > "$STATE_DIR/auto-rotate.log" 2>&1 &
  echo $! > "$STATE_DIR/auto-rotate.pid"
  ok "rotating to a fresh key every epoch (log .demo/auto-rotate.log)"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Bridge demo is running: $SEATS seats, committee 6 (4 sign). Height $H, epoch $(( H / EPOCH_BLOCKS )), ~$(( EPOCH_BLOCKS * INTERVAL / BATCH / 60 )) min per epoch.

  from any laptop on the Wi-Fi:
    bridge page   http://$LAN_IP:8080          (MetaMask: see wBDX, burn)
    wallet kit    http://$LAN_IP:8080/friend-kit.tar.gz   (Linux wallet + evm-tunnel.sh for MetaMask)
    fund them     ./demo/fund.sh <their Beldex address> 500

  watch it        ./demo/status.sh
  deposit         ./demo/deposit.sh 50            BDX → wBDX for $USER_EVM_ADDR
  burn            ./demo/burn.sh 10               wBDX → BDX to Alice
  leave           ./demo/leave.sh <node-port>     an operator asks to leave
  stop a node     ./demo/stop-node.sh <node-port>
  stop all        ./demo/demo-down.sh
────────────────────────────────────────────────────────────────────────────
EOF

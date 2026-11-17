# common.sh — shared helpers for the demo scripts. Sourced, never run.
#
# Everything the demo scripts agree on lives here: where things are, which wallet plays
# which part, and the few RPC wrappers they all use.

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL="$(cd "$DEMO_DIR/.." && pwd)"                  # utils/local-devnet
REPO="$(cd "$LOCAL/../.." && pwd)"
BC="${BC:-$HOME/Desktop/beldex/bridge-contract}"     # the wBDX contract checkout
STATE_DIR="$LOCAL/.demo"                              # logs + demo state (not in git)
mkdir -p "$STATE_DIR"
export PATH="$HOME/.foundry/bin:$PATH"

DAEMON_RPC="http://127.0.0.1:19191"
EVM_RPC="${EVM_RPC:-http://127.0.0.1:8545}"
EPOCH_BLOCKS=120                                      # devnet bridge epoch
UNLOCK_BLOCKS=360                                     # devnet bond unlock

# The demo user's EVM side: anvil's well-known account #1 (account #0 deploys and relays).
USER_EVM_ADDR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
USER_EVM_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

BIN="$REPO/build/Linux/dkg-tss-implementation/release/bin"
# The signer: the release build when there is one. A DKG generates fresh Paillier safe
# primes every time, and in a debug build that alone can take 5-20 minutes per member,
# against ~1 minute optimised — the difference between an 8-minute epoch working or not.
SIGNER_BIN="$REPO/bridge/signer/target/release/beldex-bridge-signer"
[ -x "$SIGNER_BIN" ] || SIGNER_BIN="$REPO/bridge/signer/target/debug/beldex-bridge-signer"
RELAYER_BIN="$REPO/bridge/relayer/target/debug/beldex-bridge-relayer"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$*"; }
warn() { printf '   \033[33m!!\033[0m  %s\n' "$*"; }
die()  { printf '\n\033[31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# rpc_at <port> <method> [params-json] — JSON-RPC to a daemon or wallet on localhost.
rpc_at() {
  curl -s --max-time 30 "http://127.0.0.1:$1/json_rpc" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$2\",\"params\":${3:-{\}}}"
}
jrpc() { rpc_at 19191 "$@"; }                         # the first master node's daemon

# jget <python expression over r> — read a field from a JSON-RPC reply on stdin.
jget() { python3 -c "import sys,json
d=json.load(sys.stdin); r=d.get('result')
if r is None: sys.exit('rpc error: '+json.dumps(d.get('error')))
print($1)"; }

height() { curl -s --max-time 10 "$DAEMON_RPC/get_height" | python3 -c 'import sys,json; print(json.load(sys.stdin)["height"])' 2>/dev/null; }

# The harness writes every port it used to testdata/network_state.json.
harness_state() { cat "$LOCAL/testdata/network_state.json" 2>/dev/null; }
wallet_port() {   # wallet_port <Alice|Bob|Mike|Op1..>
  harness_state | python3 -c "import sys,json
for w in json.load(sys.stdin)['wallets']:
    if w['name']=='$1': print(w['rpc_port'])"
}
mn_ports() {      # one master-node daemon RPC port per line, in harness order
  harness_state | python3 -c "import sys,json
for m in json.load(sys.stdin)['mns']: print(m['rpc_port'])"
}
wallet_address() { rpc_at "$(wallet_port "$1")" get_address '{"account_index":0}' | jget "r['address']"; }

bridge_env() {
  [ -f "$LOCAL/devnet-bridge.env" ] || die "no devnet-bridge.env — run demo-up.sh first"
  # shellcheck disable=SC1091
  . "$LOCAL/devnet-bridge.env"
}

# Roles: Alice is the demo user (deposits, receives releases); Bob pays for rotation acks;
# Mike (the faucet) pays for the gateway hand-over. The hand-over is signed early and sent
# later from Mike's wallet, so no other transaction may spend Mike's outputs in between —
# which is why the acks go through Bob instead.

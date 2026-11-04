# standby-e2e-env.sh — helpers for running the standby cycle end to end on the local devnet.
#
#   . ./standby-e2e-env.sh        (source it, from any directory)
#
# Paths: REPO is this checkout, BC the bridge-contract checkout beside it (override BC=…),
# S a scratch directory for logs (default ~/standby-e2e).
export L="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO="$(cd "$L/../.." && pwd)"
export BC="${BC:-$(cd "$REPO/.." && pwd)/bridge-contract}"
export S="${S:-$HOME/standby-e2e}"
mkdir -p "$S"
export PATH=$HOME/.foundry/bin:$PATH
EVM=http://127.0.0.1:8545
ADMIN_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
TO=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
jr() { local p="${2-}"; [ -n "$p" ] || p='{}'; curl -s "http://127.0.0.1:${3:-19191}/json_rpc" -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$1\",\"params\":$p}"; }
wport() { grep -oE "Started RPC Wallet - $1, on 127.0.0.1:[0-9]+" "$S/devnet.log" | grep -oE '[0-9]+$' | tail -1; }
envb() { . "$L/devnet-bridge.env"; }
height() { jr get_info | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])'; }
# The bridge gateway's standby picture, one line.
standby() { jr bridge_get_standby | python3 -c '
import sys,json; r=json.load(sys.stdin)["result"]
s=lambda k: (r.get(k) or "-")[:12] if isinstance(r.get(k),str) else r.get(k,"-")
att=["e%s:%s %s/%s ov=%s" % (a["epoch"],a["pgw_vk"][:8],len(a["voters"]),"ok" if a["attested_height"] else "..",a.get("overlap_with_owner","?")) for a in r.get("attestations",[])]
print("owner",s("owner_key"),"ep",s("owner_epoch"),"| standby",s("standby_key"),"seen",s("standby_last_seen_height"),"stale",s("standby_stale"),"| committee ep",s("committee_epoch"),"overlap",s("committee_overlap"),"/",s("overlap_limit"),"| att",att)'; }
evm_standby() { envb; echo "wBDX signer $(cast call $WBDX 'currentSigner()(address)' --rpc-url $EVM) standby $(cast call $WBDX 'standbySigner()(address)' --rpc-url $EVM) keyEpoch $(cast call $WBDX 'keyEpoch()(uint64)' --rpc-url $EVM)"; }
wbdx() { envb; cast call "$WBDX" 'balanceOf(address)(uint256)' $TO --rpc-url $EVM | awk '{print $1}'; }
# Deposits pay from an operator wallet (Op1): the signers keep Mike's outputs busy.
deposit() { envb; jr transfer "{\"destinations\":[{\"address\":\"$GATEWAY_ADDR\",\"amount\":$(( $1 * 1000000000 )),\"bridge_chain_id\":31337,\"bridge_evm_address\":\"$TO\"}],\"priority\":1}" "$(wport ${DEPOSIT_WALLET:-Op1})" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("deposit tx:", d.get("result",{}).get("tx_hash") or d)'; }
reserves() { envb; jr bridge_get_reserves "{\"gateway_id\":\"$GATEWAY_ID\"}" | python3 -c 'import sys,json;print("gateway_balance", json.load(sys.stdin)["result"]["gateway_balance"])'; echo "wBDX totalSupply $(cast call "$WBDX" 'totalSupply()(uint256)' --rpc-url $EVM | awk '{print $1}')"; }

# The relayer command every signer hands EVM transactions to (anvil account #0 pays gas).
relay_cmd() { echo "env RELAYER_GAS_KEY=${ADMIN_KEY#0x} RELAYER_CHAINS='[{\"chain_id\":31337,\"rpc_url\":\"$EVM\"}]' RELAYER_STATE_DIR=$S/relayer-state $REPO/bridge/relayer/target/debug/beldex-bridge-relayer relay -"; }
# Live signers on every node, supervised (they wait for shares, promote and retire themselves).
start_live() { envb; cd $L && RELAY_CMD="$(relay_cmd)" RELAY_NODES=all RELAY_STAGGER_MS=3000 \
  GATEWAY_ID=$GATEWAY_ID VIEW_SECRET=$VIEW_SECRET WBDX=$WBDX SUPERVISE=1 RETIRE_AFTER_SECS=60 \
  ACK_WALLET_RPC=http://127.0.0.1:$(wport Mike)/json_rpc ./serve-live.sh 2>&1 | grep -E 'start |serving|!!'; }
# Standby signers on every node: they generate, attest, prove and take over by themselves.
start_standby() { envb; cd $L && ROLE=standby SHARE_SUBDIR=shares-standby MESH_PORT_BASE=7000 \
  RELAY_CMD="$(relay_cmd)" RELAY_NODES=all RELAY_STAGGER_MS=3000 \
  GATEWAY_ID=$GATEWAY_ID VIEW_SECRET=$VIEW_SECRET WBDX=$WBDX SUPERVISE=1 RETIRE_AFTER_SECS=60 \
  OUTAGE_WINDOW_SECS=60 \
  ACK_WALLET_RPC=http://127.0.0.1:$(wport Mike)/json_rpc ./serve-live.sh 2>&1 | grep -E 'start |serving|!!'; }
# Which nodes hold which key now.
holders() { cd $L/testdata && for d in beldex-127.0.0.1-*/devnet; do p=${d#beldex-127.0.0.1-}; p=${p%/devnet}
  printf "%s live:%s standby:%s\n" $p "$(ls $d/shares/pgw-*.groupvk 2>/dev/null | wc -l)" "$(ls $d/shares-standby/pgw-*.groupvk 2>/dev/null | wc -l)"; done; cd - >/dev/null; }

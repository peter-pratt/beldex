#!/usr/bin/env bash
# governance.sh — the last resort for the bridge gateway: freeze it, unfreeze it, or re-point it
# to a new owner key without the old one's signature, signed by the checkpoint quorum.
#
# For when the live key AND the standby have lost their holders (or a gateway must be stopped
# now). A re-point ends any running takeover and drops the old standby unless one is named here.
# The wBDX contracts are moved separately, by their admin (breakGlassSetSigner).
#
#   ./governance.sh repoint <new_owner_eddsa_hex> [standby_eddsa_hex]
#   ./governance.sh freeze
#   ./governance.sh unfreeze
#
# Steps, each one the daemon RPC a real network would use:
#   1. gateway_governance_prepare   (any daemon): the op, the exact message and the quorum
#   2. gateway_governance_sign      (each master node's own daemon, admin RPC): one signature
#      per quorum member, made from the op itself, never from a bare hash
#   3. gateway_governance_assemble  (any daemon): checks the op exactly as consensus will
#   4. gateway_governance_submit    (a funded wallet RPC): pays the fee and relays it
# On a real network step 2 is each operator's decision: they read the summary their daemon
# prints, confirm with the team out of band that this is wanted, and send back the signature.
#
# Env: GATEWAY_ID (devnet-bridge.env)  DAEMON_RPC (default 19191)  WPORT funded wallet-rpc port
#      YES=1 to submit without asking.
set -euo pipefail
LOCAL="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL"
[ -f devnet-bridge.env ] && . ./devnet-bridge.env
GATEWAY_ID="${GATEWAY_ID:?run bootstrap-bridge.sh first}"
DAEMON_RPC="${DAEMON_RPC:-19191}"

rpc() { # port method params-json
  curl -s "http://127.0.0.1:$1/json_rpc" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$2\",\"params\":$3}"
}
result() { python3 -c "import sys,json;d=json.load(sys.stdin);r=d.get('result');e=d.get('error')
print(json.dumps(r) if r is not None else 'ERROR: '+(e or {}).get('message','no reply'))"; }
get() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }
summary() { python3 -c 'import sys,json; d=json.load(sys.stdin); print({k: v for k, v in d.items() if k not in ("op", "quorum", "status")})'; }

find_wallet() {
  [ -n "${WPORT:-}" ] && return
  for p in $(ls -d testdata/wallet-127.0.0.1-* 2>/dev/null | grep -v stderr | sed 's/.*-//' | sort -n); do
    BAL=$(rpc "$p" get_balance '{"account_index":0}' \
      | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("unlocked_balance",0))' 2>/dev/null || echo 0)
    [ "${BAL:-0}" -gt 1000000000 ] 2>/dev/null && { WPORT=$p; return; }
  done
  echo "!! no funded wallet-rpc found (set WPORT)" >&2; exit 1
}

action="${1:?usage: governance.sh repoint <new_owner_eddsa_hex> [standby_eddsa_hex] | freeze | unfreeze}"
case "$action" in
  repoint)
    owner="${2:?repoint needs the new owner eddsa key (hex)}"
    params="{\"gateway_id\":\"$GATEWAY_ID\",\"action\":\"repoint\",\"new_owner_key\":\"$owner\",\"new_owner_key_type\":\"eddsa\",\"standby_key\":\"${3:-}\"}" ;;
  freeze|unfreeze)
    params="{\"gateway_id\":\"$GATEWAY_ID\",\"action\":\"$action\"}" ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac

# 1. prepare
prep=$(rpc "$DAEMON_RPC" gateway_governance_prepare "$params" | result)
case "$prep" in ERROR:*) echo "!! prepare: ${prep#ERROR: }" >&2; exit 1 ;; esac
op=$(get op <<<"$prep"); required=$(get required <<<"$prep")
echo "prepared: $(summary <<<"$prep")"
echo "needs $required signatures from the checkpoint quorum of height $(get epoch_height <<<"$prep")"

# 2. collect a signature from every node whose daemon is in that quorum
sigs=()
for d in testdata/beldex-127.0.0.1-*/; do
  port="${d%/}"; port="${port##*-}"
  reply=$(rpc "$port" gateway_governance_sign "{\"op\":\"$op\"}" | result)
  case "$reply" in
    ERROR:*) echo "  node $port: ${reply#ERROR: }" ;;
    *) idx=$(get voter_index <<<"$reply"); sig=$(get signature <<<"$reply")
       sigs+=("\"$idx:$sig\""); echo "  node $port: signed as quorum member $idx" ;;
  esac
done
echo "collected ${#sigs[@]} of $required"

# 3. assemble and check
list=$(IFS=,; echo "${sigs[*]}")
done_=$(rpc "$DAEMON_RPC" gateway_governance_assemble "{\"op\":\"$op\",\"signatures\":[$list]}" | result)
case "$done_" in ERROR:*) echo "!! assemble: ${done_#ERROR: }" >&2; exit 1 ;; esac
final=$(get op <<<"$done_")
echo "assembled: consensus will accept it ($(get signatures <<<"$done_") signatures)"

# 4. submit
if [ "${YES:-0}" != 1 ]; then
  read -r -p "submit this $action now? [y/N] " ok
  [ "$ok" = y ] || { echo "not submitted; the finished op is:"; echo "$final"; exit 0; }
fi
find_wallet
sent=$(rpc "$WPORT" gateway_governance_submit "{\"op\":\"$final\"}" | result)
case "$sent" in ERROR:*) echo "!! submit: ${sent#ERROR: }" >&2; exit 1 ;; esac
echo "submitted: tx $(get tx_hash <<<"$sent")"

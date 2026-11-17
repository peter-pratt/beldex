#!/usr/bin/env bash
# leave.sh — a bridge operator asks to leave (unbond its seat).
#
#     ./demo/leave.sh <node-port>          # a port from the status screen's seat list
#
# The node's daemon signs the unbond request with its master-node key; the operator's own
# wallet submits it. What happens next is all consensus:
#   * at once: the seat is no longer a candidate; a queued seat (if any) takes its slot;
#   * it keeps signing with the key it already holds, until that key is retired;
#   * the next rotations' DKGs leave it out, so it never gets the new keys;
#   * its 100k bond is released after two hand-overs on each side (wBDX and gateway) AND
#     360 blocks from the request — whether or not its node is still running.
# A seated member cannot ask before the bridge's first rotation has been acknowledged.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

PORT="${1:?usage: $0 <node-port>   (see ./demo/status.sh)}"
IDX=$(mn_ports | grep -nx "$PORT" | cut -d: -f1) || true
[ -n "$IDX" ] || die "$PORT is not a master node of this devnet (ports: $(mn_ports | tr '\n' ' '))"
OP="Op$IDX"                                         # the harness gives MN i its own operator Op(i+1)
OP_PORT=$(wallet_port "$OP")
[ -n "$OP_PORT" ] || die "no operator wallet $OP for node $PORT"

if ! jrpc bridge_get_seats | jget "any(o['chain_id']!=0 for o in r.get('observed_key_epoch',[]))" | grep -q True; then
  die "no wBDX rotation has been acknowledged yet — consensus refuses a seated leave until the first one lands (wait for the first automatic rotation)"
fi

say "node $PORT ($OP) asks to leave the bridge"
HEX=$(rpc_at "$PORT" get_bridge_unbond_cmd | jget "r['unbond_hex']")
R=$(rpc_at "$OP_PORT" bridge_unbond "{\"unbond_hex\":\"$HEX\",\"priority\":1}")
echo "$R" | grep -q '"tx_hash"' || die "the wallet refused: $R"
ok "unbond tx $(echo "$R" | jget "r['tx_hash']") — watch the seat in ./demo/status.sh"
echo "   It keeps serving its current key; its bond comes back after two rotations and"
echo "   $UNLOCK_BLOCKS blocks (~$(( UNLOCK_BLOCKS * 4 / 60 )) min at the demo's pace)."

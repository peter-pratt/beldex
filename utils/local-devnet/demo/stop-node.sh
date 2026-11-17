#!/usr/bin/env bash
# stop-node.sh — switch one master node off (its daemon and its bridge signer).
#
#     ./demo/stop-node.sh <node-port>
#
# For the "an operator asked to leave and then switched off" scene. The bridge keeps
# working while at least 4 of the 6 holders of the live key are up; stopping 3 or more of
# them stops minting and releasing (the open "7+ offline" item on mainnet).
# A node that is in the NEXT committee must stay up, or that epoch's DKG fails and the
# rotation waits for the following epoch.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

PORT="${1:?usage: $0 <node-port>}"
mn_ports | grep -qx "$PORT" || die "$PORT is not a master node of this devnet"
[ "$PORT" != "19191" ] || die "19191 is the node every script and wallet talks to — pick another"

DIR="beldex-127.0.0.1-$PORT"
say "stopping node $PORT"
for pid in $(pgrep -f "beldex-bridge-signer serve" || true); do
  if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -q "$DIR/devnet"; then
    kill "$pid" && ok "signer $pid stopped"
  fi
done
pkill -f -- "--data-dir=.*/$DIR\b" && ok "daemon stopped" || warn "no daemon found for $PORT"
echo "   Its seat stays registered; consensus decides its bond exactly as if it were online."

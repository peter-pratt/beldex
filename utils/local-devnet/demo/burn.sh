#!/usr/bin/env bash
# burn.sh — the user burns wBDX and gets BDX back (minus the 0.1 BDX release fee).
#
#     ./demo/burn.sh <wBDX amount> [Beldex address]
#
# Calls redeemToNative from anvil account #1 (the demo user). Default recipient: Alice's
# wallet. The release arrives once the burn is final on anvil and the committee has signed
# and submitted it, and the Beldex block holding it has unlocked.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
. "$STATE_DIR/demo.env"; bridge_env

AMOUNT="${1:?usage: $0 <wBDX amount> [Beldex address]}"
TO="${2:-$ALICE_ADDR}"
ATOMIC=$(python3 -c "print(round(float('$AMOUNT') * 10**9))")
FEE=$(cast call "$WBDX" 'redemptionFee()(uint256)' --rpc-url "$EVM_RPC" | awk '{print $1}')

say "burn $AMOUNT wBDX → release $(python3 -c "print(($ATOMIC-$FEE)/1e9)") BDX to ${TO:0:20}…"
BEFORE=$(rpc_at "$ALICE_PORT" get_balance '{"account_index":0}' | jget "r['balance']")
cast send "$WBDX" 'redeemToNative(uint256,string)' "$ATOMIC" "$TO" \
  --rpc-url "$EVM_RPC" --private-key "$USER_EVM_KEY" >/dev/null \
  || die "the contract refused the burn (below the minimum, at or below the fee, or over a cap?)"
cast rpc anvil_mine 2 --rpc-url "$EVM_RPC" >/dev/null   # anvil only mines on demand
ok "burned on the EVM side"
[ "$TO" = "$ALICE_ADDR" ] || { echo "   (not Alice's wallet — check the recipient's balance yourself)"; exit 0; }
echo "   Alice before: $(python3 -c "print($BEFORE/1e9)") BDX — waiting for the release (Ctrl-C to stop watching)…"
for _ in $(seq 1 90); do
  sleep 5
  rpc_at "$ALICE_PORT" refresh >/dev/null 2>&1 || true
  NOW=$(rpc_at "$ALICE_PORT" get_balance '{"account_index":0}' | jget "r['balance']")
  if [ "$NOW" != "$BEFORE" ]; then
    ok "released: Alice $(python3 -c "print($BEFORE/1e9)") → $(python3 -c "print($NOW/1e9)") BDX"
    exit 0
  fi
done
warn "no release after 7.5 min — check testdata/serve-*.log"

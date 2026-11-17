#!/usr/bin/env bash
# deposit.sh — the user sends BDX to the bridge gateway and gets the same amount of wBDX.
#
#     ./demo/deposit.sh <BDX amount> [EVM address]
#
# Sent from Alice's wallet to the gateway address, with the bridge memo "31337:<EVM address>"
# (anvil's chain id; the memo is encrypted to the gateway). Default recipient: anvil account
# #1, the demo user. The wBDX appears once the deposit is final (~10 blocks) and the
# committee has signed and relayed the mint.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
. "$STATE_DIR/demo.env"; bridge_env

AMOUNT="${1:?usage: $0 <BDX amount> [EVM address]}"
TO="${2:-$USER_EVM_ADDR}"
ATOMIC=$(python3 -c "print(round(float('$AMOUNT') * 10**9))")

say "deposit $AMOUNT BDX from Alice → gateway, mint to $TO"
R=$(rpc_at "$ALICE_PORT" transfer "{\"destinations\":[{\"address\":\"$GATEWAY_ADDR\",\"amount\":$ATOMIC,
      \"bridge_chain_id\":31337,\"bridge_evm_address\":\"$TO\"}],\"priority\":1}")
echo "$R" | grep -q '"tx_hash"' || die "the wallet refused: $R"
ok "deposit tx $(echo "$R" | jget "r['tx_hash']")"
BEFORE=$(cast call "$WBDX" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$EVM_RPC" | awk '{print $1}')
echo "   wBDX before: $(python3 -c "print($BEFORE/1e9)")  — waiting for the mint (Ctrl-C to stop watching)…"
for _ in $(seq 1 90); do
  sleep 5
  NOW=$(cast call "$WBDX" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$EVM_RPC" | awk '{print $1}')
  if [ "$NOW" != "$BEFORE" ]; then
    ok "minted: wBDX balance $(python3 -c "print($BEFORE/1e9)") → $(python3 -c "print($NOW/1e9)")"
    exit 0
  fi
done
warn "no mint after 7.5 min — check .demo/relay-watch.log and testdata/serve-*.log"

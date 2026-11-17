#!/usr/bin/env bash
# fund.sh — send devnet BDX to someone's Beldex wallet (a friend joining the demo).
#
#     ./demo/fund.sh <Beldex address> [BDX amount, default 500]
#
# Paid from Alice's wallet, never Mike's: Mike's outputs back the gateway hand-over the
# rotation signs early and sends later. The BDX is spendable ~10 blocks after it arrives.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
. "$STATE_DIR/demo.env"

TO="${1:?usage: $0 <Beldex address> [BDX amount]}"
AMOUNT="${2:-500}"
ATOMIC=$(python3 -c "print(round(float('$AMOUNT') * 10**9))")
R=$(rpc_at "$ALICE_PORT" transfer "{\"destinations\":[{\"address\":\"$TO\",\"amount\":$ATOMIC}],\"priority\":1}")
echo "$R" | grep -q '"tx_hash"' || die "the transfer failed: $R"
ok "sent $AMOUNT BDX to ${TO:0:20}… (tx $(echo "$R" | jget "r['tx_hash']"))"
echo "   spendable in their wallet after ~10 blocks (refresh the wallet)"

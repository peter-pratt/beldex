#!/usr/bin/env bash
# demo-down.sh — stop everything the demo started (devnet, signers, relayer, orchestrator,
# miner, anvil). Data stays on disk; the next demo-up.sh starts fresh anyway.
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
for f in auto-rotate relay-watch harness lan-forward web; do
  [ -f "$STATE_DIR/$f.pid" ] && kill "$(cat "$STATE_DIR/$f.pid")" 2>/dev/null
done
pkill -f 'demo/auto-rotate.sh' 2>/dev/null
pkill -f 'rotate-ceremony.sh' 2>/dev/null
pkill -f 'beldex-bridge-signer' 2>/dev/null
pkill -f 'mine.sh loop' 2>/dev/null
pkill -f 'master_node_network.py' 2>/dev/null
pkill -x beldexd 2>/dev/null
pkill -f beldex-wallet-rpc 2>/dev/null
pkill -x anvil 2>/dev/null
pkill -f 'demo/lan-forward.py' 2>/dev/null
pkill -f 'http.server 8080' 2>/dev/null
sleep 2
echo "demo stopped"

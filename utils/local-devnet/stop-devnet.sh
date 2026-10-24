#!/usr/bin/env bash
# stop-devnet.sh — stop everything a devnet run started: signers, miner, harness, wallets,
# daemons, anvil. Patterns use [x] so they never match this script itself.
pkill -f 'beldex-bridge-signer [s]erve'
pkill -f 'serve-live.s[h]'
pkill -f 'mine.sh [l]oop'
pkill -INT -f 'master_node_network.p[y]'; sleep 3
pkill -f '[b]eldex-wallet-rpc'; pkill -f 'bin/[b]eldexd'; pkill -f '[a]nvil'; pkill -f 'sleep [i]nfinity'
sleep 5
pgrep -af '[b]eldexd|[a]nvil|master_node_networ[k]|[b]eldex-bridge-signer|[b]eldex-wallet-rpc' || echo "nothing running - OK"

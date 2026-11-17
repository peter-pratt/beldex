#!/usr/bin/env bash
# friend-kit.sh — package the Beldex wallet for a friend's Linux laptop (Ubuntu 24.04).
#
#     ./demo/friend-kit.sh <this machine's LAN IP> <node port on the LAN>
#
# Writes .demo/www/friend-kit.tar.gz: beldex-wallet-cli, the few libraries it needs that a
# stock Ubuntu desktop may lack, run-wallet.sh already pointed at this demo's node, and
# evm-tunnel.sh, which gives MetaMask the anvil it can reach on localhost.
# demo-up.sh calls it; the bridge page links to the file.
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

IP="${1:?usage: $0 <LAN IP> <node port>}"
PORT="${2:?usage: $0 <LAN IP> <node port>}"
KIT="$STATE_DIR/friend-kit"
rm -rf "$KIT" && mkdir -p "$KIT/lib" "$STATE_DIR/www"
cp "$BIN/beldex-wallet-cli" "$KIT/"
for lib in libboost_program_options.so.1.83.0 libboost_thread.so.1.83.0 \
           libboost_serialization.so.1.83.0 libsodium.so.23; do
  cp -L "/lib/x86_64-linux-gnu/$lib" "$KIT/lib/" 2>/dev/null || warn "could not bundle $lib"
done
cat > "$KIT/run-wallet.sh" <<EOF
#!/usr/bin/env bash
# Opens (or, the first time, creates) your demo wallet, connected to the demo node.
D="\$(cd "\$(dirname "\$0")" && pwd)"
export LD_LIBRARY_PATH="\$D/lib:\${LD_LIBRARY_PATH:-}"
if [ -f "\$D/mywallet.keys" ]; then W=(--wallet-file "\$D/mywallet"); else W=(--generate-new-wallet "\$D/mywallet"); fi
exec "\$D/beldex-wallet-cli" --devnet --daemon-address $IP:$PORT --trusted-daemon "\${W[@]}" --password '' "\$@"
EOF
cp "$DEMO_DIR/lan-forward.py" "$KIT/"
cat > "$KIT/evm-tunnel.sh" <<EOF
#!/usr/bin/env bash
# Keep this running while you use the bridge page. MetaMask only accepts a plain-http network
# address on localhost, so 127.0.0.1:8545 here is relayed to the demo laptop's anvil.
if ss -ltn 2>/dev/null | grep -q '127.0.0.1:8545 \\|0.0.0.0:8545 \\|\\*:8545 \\|\\[::\\]:8545 '; then
  echo "!! something on THIS laptop already listens on port 8545:"
  ss -ltnp 2>/dev/null | grep ':8545 ' | sed 's/^/     /'
  echo "   If it is your own anvil/hardhat, stop it (pkill -x anvil) — MetaMask would talk to it"
  echo "   instead of the demo. If it is python3 (this tunnel), it is already running: nothing to do."
  exit 1
fi
exec python3 "\$(cd "\$(dirname "\$0")" && pwd)/lan-forward.py" 8545 8545 $IP 127.0.0.1
EOF
chmod +x "$KIT/run-wallet.sh" "$KIT/beldex-wallet-cli" "$KIT/evm-tunnel.sh"
tar -C "$STATE_DIR" -czf "$STATE_DIR/www/friend-kit.tar.gz" friend-kit
ok "friend kit: .demo/www/friend-kit.tar.gz ($(du -h "$STATE_DIR/www/friend-kit.tar.gz" | cut -f1))"

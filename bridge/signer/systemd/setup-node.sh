#!/usr/bin/env bash
# setup-node.sh — prepare a server for the Beldex bridge services, and check it before starting.
#
#   sudo ./setup-node.sh node <seat>      a bridge seat: user, folders, settings files, share
#                                         key, the serve/dkg/standby units
#   sudo ./setup-node.sh runner           the runner: folders, settings file, the relay-watch and
#                                         handover-submit units
#   sudo ./setup-node.sh check <seat>     a seat's settings and files, before starting it
#   sudo ./setup-node.sh check-runner     the runner's
#
# <seat> is a short name for the seat (e.g. its master node's name), used in file and unit
# names. It installs nothing that already exists and starts nothing: it prints what to do next.
# The binaries (/usr/bin/beldex-bridge-signer, /usr/bin/beldex-bridge-relayer) are built and
# installed separately.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/beldex
USER_NAME=beldex
SIGNER_BIN=/usr/bin/beldex-bridge-signer
RELAYER_BIN=/usr/bin/beldex-bridge-relayer

die()  { echo "!! $*" >&2; exit 1; }
ok()   { echo "   ok  $*"; }
bad()  { echo "   !!  $*"; FAILED=1; }
need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo)"; }
seat_ok() { [[ "$1" =~ ^[A-Za-z0-9_.-]+$ ]] || die "seat name '$1': letters, digits, . _ - only"; }

ensure_user() {
  id "$USER_NAME" >/dev/null 2>&1 && return
  useradd --system --home-dir /var/lib/beldex --shell /usr/sbin/nologin "$USER_NAME"
  ok "created the system user $USER_NAME"
}

# install_file <src> <dst> <mode> <owner:group>: only if <dst> does not exist yet.
install_file() {
  if [ -e "$2" ]; then ok "$2 exists (left as is)"; return; fi
  install -m "$3" -o "${4%%:*}" -g "${4##*:}" "$1" "$2"
  ok "installed $2"
}

install_units() {
  for u in "$@"; do
    install -m 0644 "$HERE/$u" "/etc/systemd/system/$u"
  done
  systemctl daemon-reload
  ok "units installed: $*"
}

# A file holding a secret: present, a regular file, owned by $2, readable by its owner only.
check_secret_file() {
  local f="$1" owner="$2" what="$3"
  [ -n "$f" ] || { bad "$what: not set"; return; }
  [ -f "$f" ] && [ ! -L "$f" ] || { bad "$what: $f is missing (or a link)"; return; }
  [ "$(stat -c %U "$f")" = "$owner" ] || bad "$what: $f must be owned by $owner"
  [ "$(( 8#$(stat -c %a "$f") & 8#077 ))" = 0 ] || bad "$what: $f is readable by others; chmod 600 it"
  ok "$what: $f"
}

# Every variable an env file sets, and none still a <placeholder>.
check_env_file() {
  local f="$1"; shift
  [ -f "$f" ] || { bad "$f is missing"; return 1; }
  if grep -nE '^[A-Z_]+=.*<[^>]*>' "$f" >/dev/null; then
    bad "$f still has placeholders:"; grep -nE '^[A-Z_]+=.*<[^>]*>' "$f" | sed 's/^/        /'
  fi
  local k
  for k in "$@"; do
    grep -qE "^$k=." "$f" || bad "$f: $k is not set"
  done
}

envval() { grep -E "^$2=" "$1" 2>/dev/null | tail -1 | cut -d= -f2-; }

check_json() {
  local name="$1" value="$2"
  [ -n "$value" ] || return
  if command -v python3 >/dev/null; then
    python3 -c 'import json,sys; v=json.loads(sys.argv[1]); assert isinstance(v,list) and v' "$value" 2>/dev/null \
      && ok "$name is a JSON list" || bad "$name is not a valid, non-empty JSON list"
  fi
}

check_daemon() {
  local url="$1"
  [ -n "$url" ] || return
  if command -v curl >/dev/null && curl -s -m 5 "${url%/}/json_rpc" -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' | grep -q '"height"'; then
    ok "beldexd answers at $url"
  else
    bad "beldexd does not answer at $url"
  fi
}

cmd_node() {
  need_root; local seat="$1"; seat_ok "$seat"
  ensure_user
  install -d -m 0750 -o root -g "$USER_NAME" "$ETC"
  local base="/var/lib/beldex/bridge-$seat"
  for d in "$base" "$base/live" "$base/dkg" "$base/standby"; do
    install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$d"
  done
  ok "folders under $base"

  local env="$ETC/bridge-signer-$seat.env"
  if [ ! -e "$env" ]; then
    sed "s#<seat>#$seat#g" "$HERE/bridge-signer.env.example" > "$env.tmp"
    install -m 0640 -o root -g "$USER_NAME" "$env.tmp" "$env"; rm -f "$env.tmp"
    ok "installed $env (fill in every <...>)"
  else
    ok "$env exists (left as is)"
  fi
  local dkg="$ETC/bridge-dkg-$seat.env" standby="$ETC/bridge-standby-$seat.env" tmp
  tmp=$(mktemp)
  printf 'BRIDGE_SIGNER_DKG_PORT_BASE=7000\nBRIDGE_SIGNER_STATUS_LISTEN=127.0.0.1:9101\n' > "$tmp"
  install_file "$tmp" "$dkg" 0640 "root:$USER_NAME"
  printf '%s\n' "BRIDGE_SIGNER_ROLE=standby" "BRIDGE_SIGNER_SHARE_DIR=$base/shares-standby" \
    "BRIDGE_SIGNER_PROMOTE_TO=$base/shares" "BRIDGE_SIGNER_MESH_PORT_BASE=8000" \
    "BRIDGE_SIGNER_STATUS_LISTEN=127.0.0.1:9102" "BRIDGE_SIGNER_OUTAGE_WINDOW_SECS=600" > "$tmp"
  install_file "$tmp" "$standby" 0640 "root:$USER_NAME"
  rm -f "$tmp"

  # The key that seals the seat's shares. Never replaced: shares sealed under it would no longer
  # open. Back it up apart from the shares (a copy of both together is what it protects against).
  local key="$ETC/bridge-share-$seat.key"
  if [ -e "$key" ]; then
    ok "$key exists (left as is)"
  else
    ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$key" )
    chown root:root "$key"; chmod 0600 "$key"
    ok "made the share key $key (root only; back it up apart from the shares)"
  fi

  install_units beldex-bridge-serve@.service beldex-bridge-dkg@.service beldex-bridge-standby@.service
  cat <<EOF

Next, for seat $seat:
  1. Fill in $env (every <...>), and for testnet set
     BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=360 and BRIDGE_SIGNER_COMMITTEE_THRESHOLD=3.
  2. Start the seat's fee wallet (beldex-wallet-rpc --rpc-login user:password --rpc-bind-ip 127.0.0.1),
     fund it with a little BDX, and put user:password in $ETC/bridge-fee-wallet-$seat.login
     (owner $USER_NAME, mode 600).
  3. Open the mesh ports to the other seats: 6000-6299 (live), 7000-7299 (key making),
     8000-8299 (standby).
  4. sudo $0 check $seat
  5. sudo systemctl enable --now beldex-bridge-serve@$seat beldex-bridge-dkg@$seat beldex-bridge-standby@$seat
EOF
}

cmd_runner() {
  need_root
  ensure_user
  install -d -m 0750 -o root -g "$USER_NAME" "$ETC"
  for d in /var/lib/beldex-bridge /var/lib/beldex-bridge/relay /var/lib/beldex-bridge/relay/state \
           /var/lib/beldex-bridge/handover /var/lib/beldex-bridge/handover/records; do
    install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$d"
  done
  ok "folders under /var/lib/beldex-bridge"
  install_file "$HERE/bridge-runner.env.example" "$ETC/bridge-runner.env" 0640 "root:$USER_NAME"
  install_units beldex-bridge-relay-watch.service beldex-bridge-handover-submit.service
  cat <<EOF

Next, for the runner:
  1. Fill in $ETC/bridge-runner.env (every <...>).
  2. Put the EVM gas key (64 hex) in $ETC/relayer-gas.key (owner root, mode 600) and fund its
     address with gas on every chain.
  3. Start the hand-over wallet (beldex-wallet-rpc --rpc-login user:password --rpc-bind-ip 127.0.0.1),
     fund it, and put user:password in $ETC/bridge-handover-wallet.login (owner $USER_NAME, mode 600).
  4. Start this machine's beldexd with --lmq-public tcp://0.0.0.0:<port>, and open that port and
     the hand-over port (18090) to the seats only.
  5. sudo $0 check-runner
  6. sudo systemctl enable --now beldex-bridge-relay-watch beldex-bridge-handover-submit
EOF
}

cmd_check() {
  need_root; local seat="$1"; seat_ok "$seat"; FAILED=0
  local env="$ETC/bridge-signer-$seat.env"
  echo "== seat $seat"
  [ -x "$SIGNER_BIN" ] && ok "$SIGNER_BIN" || bad "$SIGNER_BIN is missing"
  check_env_file "$env" BRIDGE_SIGNER_BELDEXD_RPC_URL BRIDGE_SIGNER_OXENMQ_ENDPOINT BRIDGE_SIGNER_MN_KEY_FILE \
    BRIDGE_SIGNER_SELF_MN_PUBKEY BRIDGE_SIGNER_GENESIS_HASH BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS \
    BRIDGE_SIGNER_COMMITTEE_THRESHOLD BRIDGE_SIGNER_GATEWAY_ID BRIDGE_SIGNER_GATEWAY_VIEW_SECRET \
    BRIDGE_SIGNER_EVM_CHAINS BRIDGE_SIGNER_MINT_BUS_ENDPOINT BRIDGE_SIGNER_HANDOVER_BUILDER \
    BRIDGE_SIGNER_SHARE_DIR BRIDGE_SIGNER_ACK_WALLET_RPC BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE \
    BRIDGE_SIGNER_MESH_PORT_BASE BRIDGE_SIGNER_SERVE_LIVE || true
  check_env_file "$ETC/bridge-dkg-$seat.env" BRIDGE_SIGNER_DKG_PORT_BASE || true
  check_env_file "$ETC/bridge-standby-$seat.env" BRIDGE_SIGNER_ROLE BRIDGE_SIGNER_SHARE_DIR \
    BRIDGE_SIGNER_PROMOTE_TO BRIDGE_SIGNER_MESH_PORT_BASE || true
  for k in BRIDGE_SIGNER_MESH_USE_CURVE BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES BRIDGE_SIGNER_SHARE_KEY \
           BRIDGE_SIGNER_BELDEX_CONFIRMATIONS; do
    grep -qE "^$k=" "$env" 2>/dev/null && bad "$k is a test-network setting: remove it"
  done
  grep -q depth_only_finality "$env" 2>/dev/null && bad "depth_only_finality is a test-network setting: remove it"
  check_json BRIDGE_SIGNER_EVM_CHAINS "$(envval "$env" BRIDGE_SIGNER_EVM_CHAINS)"
  check_secret_file "$ETC/bridge-share-$seat.key" root "share key"
  check_secret_file "$(envval "$env" BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE)" "$USER_NAME" "fee wallet login"
  local mn; mn="$(envval "$env" BRIDGE_SIGNER_MN_KEY_FILE)"
  if [ -n "$mn" ] && sudo -u "$USER_NAME" test -r "$mn"; then ok "MN key $mn readable by $USER_NAME"
  else bad "MN key ${mn:-(not set)} is not readable by $USER_NAME"; fi
  local share; share="$(envval "$env" BRIDGE_SIGNER_SHARE_DIR)"
  case "$share" in "/var/lib/beldex/"*) ok "share dir $share" ;; *) bad "share dir ${share:-(not set)} must be under /var/lib/beldex (the units may write only there)" ;; esac
  check_daemon "$(envval "$env" BRIDGE_SIGNER_BELDEXD_RPC_URL)"
  [ "$FAILED" = 0 ] && echo "seat $seat: ready to start" || { echo "seat $seat: fix the !! lines first"; exit 1; }
}

cmd_check_runner() {
  need_root; FAILED=0
  local env="$ETC/bridge-runner.env"
  echo "== runner"
  for b in "$SIGNER_BIN" "$RELAYER_BIN"; do [ -x "$b" ] && ok "$b" || bad "$b is missing"; done
  check_env_file "$env" BRIDGE_SIGNER_OXENMQ_ENDPOINT BRIDGE_SIGNER_BELDEXD_RPC_URL BRIDGE_SIGNER_RELAY_CMD \
    RELAYER_CHAINS RELAYER_STATE_DIR BRIDGE_SIGNER_HANDOVER_WALLET_RPC BRIDGE_SIGNER_HANDOVER_WALLET_LOGIN_FILE \
    BRIDGE_SIGNER_RELEASE_GATEWAY BRIDGE_SIGNER_EVM_CHAINS BRIDGE_SIGNER_HANDOVER_LISTEN \
    BRIDGE_SIGNER_HANDOVER_DIR || true
  grep -qE '^RELAYER_GAS_KEY=' "$env" 2>/dev/null && bad "RELAYER_GAS_KEY in $env: use $ETC/relayer-gas.key instead"
  check_json RELAYER_CHAINS "$(envval "$env" RELAYER_CHAINS)"
  check_json BRIDGE_SIGNER_EVM_CHAINS "$(envval "$env" BRIDGE_SIGNER_EVM_CHAINS)"
  check_secret_file "$ETC/relayer-gas.key" root "relayer gas key"
  check_secret_file "$(envval "$env" BRIDGE_SIGNER_HANDOVER_WALLET_LOGIN_FILE)" "$USER_NAME" "hand-over wallet login"
  check_daemon "$(envval "$env" BRIDGE_SIGNER_BELDEXD_RPC_URL)"
  [ "$FAILED" = 0 ] && echo "runner: ready to start" || { echo "runner: fix the !! lines first"; exit 1; }
}

case "${1:-}" in
  node)         [ -n "${2:-}" ] || die "usage: $0 node <seat>"; cmd_node "$2" ;;
  runner)       cmd_runner ;;
  check)        [ -n "${2:-}" ] || die "usage: $0 check <seat>"; cmd_check "$2" ;;
  check-runner) cmd_check_runner ;;
  *) sed -n '2,15p' "$0"; exit 1 ;;
esac

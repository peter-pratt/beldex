#!/usr/bin/env bash
# standby.sh — standby failover for the bridge keys (both chains).
#
# If enough of the live key's holders vanish at once (7 of 20 on mainnet, 3 of 6 here),
# the live key can sign nothing, not even its own rotation. A standby key, generated in
# advance by another committee, takes over after a delay in which a live key can cancel.
#
#   ./standby.sh register   the LIVE key names the standby (shares-standby) on the wBDX
#                           contract and as the gateway's standby owner
#   ./standby.sh guard      live side: cancel any running takeover the live key can still
#                           sign against (loops; ONCE=1 for a single pass)
#   ./standby.sh watch      standby side: when the live key's holders are unreachable,
#                           begin the takeover on both chains, complete it after the delay,
#                           promote shares-standby and restart the signers (loops)
#   ./standby.sh begin      begin a takeover by hand (a live key's guard cancels it)
#   ./standby.sh status     both chains' standby and takeover state
#
# Generate the standby key first, into its own tree, at an epoch whose committee differs
# from the live key's as much as possible:
#   SHARE_SUBDIR=shares-standby MESH_PORT_BASE=7000 ./dkg-next.sh <unused-keygen>
#
# Env:
#   STANDBY_SUBDIR   standby share tree (default shares-standby)
#   EVM_RPC          (default http://127.0.0.1:8545)   EVM_KEY  key that pays EVM gas
#   DAEMON_RPC       (default 19191)                   WPORT    funded wallet-rpc port
#   POLL_SECS        loop interval (default 15)        MESH_PORT_BASE  signing mesh (7000)
#   EVM_TAKEOVER_DELAY  on `register`, set the contract's takeover delay (seconds, admin = EVM_KEY)
set -euo pipefail
LOCAL="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL"
export PATH="$HOME/.foundry/bin:$PATH"

[ -f devnet-bridge.env ] && . ./devnet-bridge.env
WBDX="${WBDX:?run bootstrap-bridge.sh first}"
GATEWAY_ID="${GATEWAY_ID:?run bootstrap-bridge.sh first}"
STANDBY_SUBDIR="${STANDBY_SUBDIR:-shares-standby}"
EVM_RPC="${EVM_RPC:-http://127.0.0.1:8545}"
EVM_KEY="${EVM_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DAEMON_RPC="${DAEMON_RPC:-19191}"
POLL_SECS="${POLL_SECS:-15}"
export MESH_PORT_BASE="${MESH_PORT_BASE:-7000}"

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }

drpc() {
  curl -s "http://127.0.0.1:$DAEMON_RPC/json_rpc" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$1\",\"params\":$2}"
}
wrpc() {
  curl -s "http://127.0.0.1:$WPORT/json_rpc" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$1\",\"params\":$2}"
}
field() { python3 -c "import sys,json;d=json.load(sys.stdin);r=d.get('result') or {};print(r.get('$1',''))"; }

find_wallet() {
  [ -n "${WPORT:-}" ] && return
  for p in $(ls -d testdata/wallet-127.0.0.1-* 2>/dev/null | grep -v stderr | sed 's/.*-//' | sort -n); do
    BAL=$(curl -s "http://127.0.0.1:$p/json_rpc" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{"account_index":0}}' \
      | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("unlocked_balance",0))' 2>/dev/null || echo 0)
    [ "${BAL:-0}" -gt 1000000000 ] 2>/dev/null && { WPORT=$p; return; }
  done
  echo "!! no funded wallet-rpc found" >&2; exit 1
}

# ---- keys ---------------------------------------------------------------------------
any_file() { ls testdata/beldex-127.0.0.1-*/devnet/"$1"/$2 2>/dev/null | head -1; }
pgw_vk() { local f; f="$(any_file "$1" 'pgw-*.groupvk')"; [ -n "$f" ] && od -An -v -tx1 < "$f" | tr -d ' \n'; }
pevm_addr() {
  local f gk unc
  f="$(any_file "$1" 'pevm-*.groupkey')"; [ -n "$f" ] || return 1
  gk="$(od -An -v -tx1 < "$f" | tr -d ' \n')"
  unc=$(python3 - "$gk" <<'EOF'
import sys
c = bytes.fromhex(sys.argv[1]); p = 2**256 - 2**32 - 977
x = int.from_bytes(c[1:], 'big'); y = pow((pow(x, 3, p) + 7) % p, (p + 1) // 4, p)
if (y & 1) != (c[0] & 1): y = p - y
print((x.to_bytes(32,'big') + y.to_bytes(32,'big')).hex())
EOF
)
  echo "0x$(cast keccak "0x$unc" | sed 's/^0x//' | cut -c25-64)"
}

# Threshold signatures from one share tree. Each fails (returns 1) when the tree's holders
# cannot reach the threshold, which for the live tree is exactly "the live key is silent".
# sign-pevm.sh stops any signing run already going, so the guard and the watch (which run
# side by side on this one host) take turns through a lock.
locked() { flock testdata/.standby-sign.lock "$@"; }
# The signer set: the first `threshold` holders that still have the tree. The default (the
# first `threshold` committee indices) stalls as soon as one of those is the holder that is gone.
signer_set() { # <subdir>
  local t
  t=$(python3 -c "import json;print(json.load(open('$(any_file "$1" committee.json)'))['threshold'])") || return 1
  ls testdata/beldex-127.0.0.1-*/devnet/"$1"/pevm-*.keyshare 2>/dev/null \
    | sed -E 's/.*pevm-([0-9]+)\.keyshare/\1/' | sort -n | head -"$t" | paste -sd, -
}
sign_evm() { # <subdir> <preimage-hex> <label>
  local sig
  rm -f testdata/"$3"-sign-*.log
  SHARE_SUBDIR="$1" LOG_PREFIX="$3" BRIDGE_SIGNER_SIGN_TIMEOUT_SECS=90 \
    BRIDGE_SIGNER_SIGN_SIGNERS="$(signer_set "$1")" locked ./sign-pevm.sh raw "$2" > "testdata/$3.out" 2>&1 || return 1
  sig=$(grep -h 'eth signature: 0x' testdata/"$3"-sign-*.log 2>/dev/null | sed 's/.*: //' | sort -u | head -1)
  [ "${#sig}" -eq 132 ] || return 1
  echo "$sig"
}
sign_pgw() { # <subdir> <hash-hex> <label>
  local sig
  rm -f testdata/"$3"-sign-*.log
  SHARE_SUBDIR="$1" LOG_PREFIX="$3" BRIDGE_SIGNER_SIGN_TIMEOUT_SECS=90 \
    BRIDGE_SIGNER_SIGN_SIGNERS="$(signer_set "$1")" locked ./sign-pevm.sh pgw "0x$2" > "testdata/$3.out" 2>&1 || return 1
  sig=$(grep -h '^Pgw signature :' testdata/"$3"-sign-*.log 2>/dev/null | sed 's/.*: *//' | tr -d ' \r' | sort -u | head -1)
  [ "${#sig}" -eq 128 ] || return 1
  echo "$sig"
}

# ---- wBDX contract --------------------------------------------------------------------
call() { cast call "$WBDX" "$@" --rpc-url "$EVM_RPC" | awk '{print $1}'; }
send() { cast send "$WBDX" "$@" --private-key "$EVM_KEY" --rpc-url "$EVM_RPC" 2>&1 | grep -E '^status' | awk '{print $2}'; }
chain_id() { cast chain-id --rpc-url "$EVM_RPC"; }
evm_now() { cast block latest -f timestamp --rpc-url "$EVM_RPC"; }

evm_set_standby() { # <live-subdir> <standby-addr>
  local nonce deadline pre sig
  nonce=$(( $(call 'rotationNonce()(uint64)') + 1 )); deadline=$(( $(evm_now) + 3600 ))
  pre=$(cast abi-encode 'f(bytes32,uint256,address,uint64,address,uint64,uint256)' \
    "$(call 'STANDBY_TAG()(bytes32)')" "$(chain_id)" "$WBDX" "$(call 'keyEpoch()(uint64)')" "$2" "$nonce" "$deadline")
  sig=$(sign_evm "$1" "$pre" standby-set) || { echo "!! the live key could not sign setStandby" >&2; return 1; }
  [ "$(send 'setStandby(address,uint64,uint256,bytes)' "$2" "$nonce" "$deadline" "$sig")" = 1 ]
}
evm_begin() {
  local pre sig
  pre=$(cast abi-encode 'f(bytes32,uint256,address,uint64,address,uint64)' \
    "$(call 'TAKEOVER_BEGIN_TAG()(bytes32)')" "$(chain_id)" "$WBDX" "$(call 'keyEpoch()(uint64)')" \
    "$(call 'standbySigner()(address)')" "$(( $(call 'takeoverNonce()(uint64)') + 1 ))")
  sig=$(sign_evm "$STANDBY_SUBDIR" "$pre" takeover-begin) || return 1
  [ "$(send 'beginStandbyTakeover(bytes)' "$sig")" = 1 ]
}
evm_cancel() { # signed by the LIVE key: fails if it is silent
  local pre sig
  pre=$(cast abi-encode 'f(bytes32,uint256,address,uint64,uint64)' \
    "$(call 'TAKEOVER_CANCEL_TAG()(bytes32)')" "$(chain_id)" "$WBDX" "$(call 'keyEpoch()(uint64)')" \
    "$(call 'takeoverNonce()(uint64)')")
  sig=$(sign_evm shares "$pre" takeover-cancel) || return 1
  [ "$(send 'cancelStandbyTakeover(bytes)' "$sig")" = 1 ]
}
evm_complete() {
  local pre sig
  pre=$(cast abi-encode 'f(bytes32,uint256,address,uint64,address)' \
    "$(call 'TAKEOVER_COMPLETE_TAG()(bytes32)')" "$(chain_id)" "$WBDX" "$(( $(call 'keyEpoch()(uint64)') + 1 ))" \
    "$(call 'standbySigner()(address)')")
  sig=$(sign_evm "$STANDBY_SUBDIR" "$pre" takeover-complete) || return 1
  [ "$(send 'completeStandbyTakeover(bytes)' "$sig")" = 1 ]
}
evm_running() { [ "$(call 'takeoverStartedAt()(uint256)')" != 0 ]; }
evm_ready()   { [ "$(evm_now)" -ge $(( $(call 'takeoverStartedAt()(uint256)') + $(call 'standbyTakeoverDelayOrDefault()(uint256)') )) ]; }

# ---- gateway --------------------------------------------------------------------------
gw() { drpc get_gateway_info "{\"gateway_address\":\"$GATEWAY_ID\"}" | field "$1"; }
l1_height() { drpc get_info '{}' | field height; }

# Build, threshold-sign and submit a descriptor update. <owner-vk> <standby-vk|""> <takeover|""> <signing-subdir> <label>
l1_update() {
  local standby_json="" build hash meta sig sub
  find_wallet
  [ -n "$2" ] && standby_json=",\"standby_owner_key_type\":\"eddsa\",\"standby_owner_key\":\"$2\""
  meta="$(gw meta_info)"
  build=$(wrpc gateway_update_descriptor "{\"gateway_id\":\"$GATEWAY_ID\",\"owner_key_type\":\"eddsa\",
    \"owner_key\":\"$1\",\"bridge_reserve\":true,\"meta_info\":\"$meta\"$standby_json,\"takeover\":\"$3\",\"priority\":1}")
  hash=$(echo "$build" | field hash_to_sign)
  [ -n "$hash" ] || { echo "!! gateway update build failed: $build" >&2; return 1; }
  sig=$(sign_pgw "$4" "$hash" "$5") || return 1
  sub=$(wrpc gateway_submit_descriptor_update \
    "{\"tx_metadata\":\"$(echo "$build" | field tx_metadata)\",\"signature\":\"$sig\",\"signature_type\":\"eddsa\"}")
  echo "$sub" | grep -q '"tx_hash"' || { echo "!! gateway update refused: $sub" >&2; return 1; }
}
l1_running() { [ "$(gw takeover_started_height)" != 0 ]; }
l1_ready()   { [ "$(l1_height)" -ge "$(gw takeover_ready_height)" ]; }
wait_l1() { # until <condition-fn> holds, or ~5 min
  for _ in $(seq 1 60); do "$@" && return 0; sleep 5; done; return 1
}

# ---- liveness of the live key ---------------------------------------------------------
# How many of the live key's holders answer on their coordinator mesh port (6200 + index on
# this devnet). Below the threshold the live key cannot sign; the takeover is then begun,
# and it is the live key's chance to prove otherwise by cancelling.
live_holders_reachable() {
  local c n up=0 i
  c="$(any_file shares committee.json)"; [ -n "$c" ] || { echo 0; return; }
  n=$(python3 -c "import json;print(len(json.load(open('$c'))['members']))")
  for i in $(seq 0 $((n - 1))); do
    (exec 3<>/dev/tcp/127.0.0.1/$((6200 + i))) 2>/dev/null && up=$((up + 1))
  done
  echo "$up"
}
live_threshold() { python3 -c "import json;print(json.load(open('$(any_file shares committee.json)'))['threshold'])"; }

status() {
  echo "wBDX    signer $(call 'currentSigner()(address)') epoch $(call 'keyEpoch()(uint64)') | standby $(call 'standbySigner()(address)') | takeover started $(call 'takeoverStartedAt()(uint256)') (delay $(call 'standbyTakeoverDelayOrDefault()(uint256)')s)"
  echo "gateway owner $(gw owner_key) | standby $(gw standby_owner_key) | takeover started $(gw takeover_started_height) ready $(gw takeover_ready_height) (height $(l1_height))"
  [ -n "$(any_file shares committee.json)" ] && echo "live key holders reachable: $(live_holders_reachable) of threshold $(live_threshold)"
  return 0
}

case "${1:-}" in
  register)
    SB_ADDR=$(pevm_addr "$STANDBY_SUBDIR") || { echo "!! no $STANDBY_SUBDIR Pevm key — run the standby DKG first" >&2; exit 1; }
    SB_VK=$(pgw_vk "$STANDBY_SUBDIR"); LIVE_VK=$(pgw_vk shares)
    if [ -n "${EVM_TAKEOVER_DELAY:-}" ]; then
      [ "$(send 'setStandbyTakeoverDelay(uint256)' "$EVM_TAKEOVER_DELAY")" = 1 ] || { echo "!! could not set the delay" >&2; exit 1; }
    fi
    say "wBDX: the live key names standby $SB_ADDR"
    evm_set_standby shares "$SB_ADDR" || exit 1
    say "gateway: the live Pgw names standby owner $SB_VK"
    l1_update "$LIVE_VK" "$SB_VK" "" shares standby-gw-set || exit 1
    wait_l1 eval '[ "$(gw standby_owner_key)" = "$SB_VK" ]' || { echo "!! the gateway update did not land" >&2; exit 1; }
    status ;;

  guard)
    say "guard: cancelling any takeover while the live key can sign"
    while :; do
      if evm_running; then
        if evm_cancel; then say "wBDX: takeover cancelled by the live key"; else say "wBDX: takeover running and the live key cannot sign"; fi
      fi
      if l1_running; then
        if l1_update "$(gw owner_key)" "$(gw standby_owner_key)" "" shares takeover-gw-cancel; then
          say "gateway: takeover cancelled by the live owner"
        else
          say "gateway: takeover running and the live owner cannot sign"
        fi
      fi
      [ "${ONCE:-0}" = 1 ] && break
      sleep "$POLL_SECS"
    done ;;

  watch)
    SB_VK=$(pgw_vk "$STANDBY_SUBDIR")
    [ -n "$SB_VK" ] || { echo "!! no $STANDBY_SUBDIR — run the standby DKG first" >&2; exit 1; }
    # Restarted part-way through a takeover, the gateway may already belong to the standby.
    [ "$(gw standby_owner_key)" = "$SB_VK" ] || [ "$(gw owner_key)" = "$SB_VK" ] \
      || { echo "!! the gateway does not name this standby — run register" >&2; exit 1; }
    T=$(live_threshold); low=0
    say "watch: live key needs $T holders; checking every ${POLL_SECS}s"
    while :; do
      up=$(live_holders_reachable)
      if [ "$up" -lt "$T" ]; then low=$((low + 1)); else low=0; fi
      if ! evm_running && ! l1_running; then
        if [ "$low" -ge 2 ]; then
          say "live key holders reachable: $up < $T on two checks — beginning the takeover"
          evm_begin && say "wBDX: takeover begun" || say "!! wBDX begin failed"
          l1_update "$(gw owner_key)" "$SB_VK" begin "$STANDBY_SUBDIR" takeover-gw-begin && say "gateway: takeover begun" || say "!! gateway begin failed"
        fi
      else
        if evm_running && evm_ready; then
          evm_complete && say "wBDX: takeover COMPLETE — the standby is the mint key" || say "!! wBDX complete failed"
        fi
        # A submitted complete takes a block or two to mine; do not send a second one meanwhile.
        if l1_running && l1_ready && [ "$(l1_height)" -ge "${l1_sent_at:-0}" ]; then
          l1_sent_at=$(( $(l1_height) + 3 ))
          l1_update "$SB_VK" "" complete "$STANDBY_SUBDIR" takeover-gw-complete \
            && say "gateway: takeover COMPLETE submitted" || say "!! gateway complete failed"
        fi
      fi
      if [ "$(call 'currentSigner()(address)' | tr A-F a-f)" = "$(pevm_addr "$STANDBY_SUBDIR" | tr A-F a-f)" ] \
         && [ "$(gw owner_key)" = "$SB_VK" ]; then
        say "both chains answer to the standby key: promoting $STANDBY_SUBDIR and restarting the signers"
        SUBDIR="$STANDBY_SUBDIR" ./promote-shares.sh > testdata/standby-promote.log 2>&1 || { echo "!! promotion failed: testdata/standby-promote.log" >&2; exit 1; }
        if [ -s testdata/serve-live.last ]; then
          ( set -a; . testdata/serve-live.last; set +a; ./serve-live.sh ) > testdata/standby-serve-restart.log 2>&1 \
            && say "signers restarted on the new key" || say "!! restart failed: testdata/standby-serve-restart.log"
        fi
        status
        exit 0
      fi
      sleep "$POLL_SECS"
    done ;;

  begin)
    # Begin a takeover by hand (both chains). Harmless against a live key: the guard cancels.
    SB_VK=$(pgw_vk "$STANDBY_SUBDIR")
    evm_begin && say "wBDX: takeover begun" || { echo "!! wBDX begin failed" >&2; exit 1; }
    l1_update "$(gw owner_key)" "$SB_VK" begin "$STANDBY_SUBDIR" takeover-gw-begin && say "gateway: takeover begun" \
      || { echo "!! gateway begin failed" >&2; exit 1; }
    wait_l1 l1_running || echo "!! the gateway begin did not land" >&2
    status ;;

  status) status ;;
  *) sed -n '2,25p' "$0"; exit 1 ;;
esac

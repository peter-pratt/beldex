#!/usr/bin/env bash
# gateway-handover.sh — hand the gateway's spending rights to the INCOMING committee.
#
#     runlog ./gateway-handover.sh <new-Pgw-group-vk-hex>
#     runlog ./gateway-handover.sh --sign-only <new-Pgw-group-vk-hex> <file>
#     runlog ./gateway-handover.sh --submit <file>
#
# --sign-only builds and signs the hand-over now and keeps it in <file> without sending it;
# --submit sends one kept that way. The rotation ceremony signs while the outgoing key is
# certainly live (right after it authorises the rotation) and sends only once the
# activation is verified, so its holders need not stay online through the challenge window.
# Sending needs no key, only the same wallet that built it.
#
# WHY THIS EXISTS. Consensus checks every gateway withdrawal against the gateway's
# CURRENT owner key (gateway_utils.cpp, "gateway input signature verification failed").
# A rotation gives the incoming committee a brand-new `Pgw` from its fresh DKG, but
# nothing on chain moves the owner key to match — so the moment the old shares are
# retired, every release stops. The committee keeps minting and can no longer pay out.
#
# WHAT IT DOES NOT CHANGE. The gateway ADDRESS. `address_id` is set once at registration
# and is the key the account is stored under; an update only appends a descriptor to
# `descriptor_history`. Depositors keep using the same address forever.
#
# WHEN TO RUN IT. AFTER the on-chain rotation is verified, BEFORE the share promotion —
# the authorisation must be signed by the OUTGOING key, which lives in devnet/shares
# until promote-shares.sh moves it. Running it after the promotion means the only key
# that could have signed the handover is no longer the one the scripts reach for.
#
# Env:
#   GATEWAY_ID       hex gateway id            (default: from devnet-bridge.env)
#   WPORT            a funded wallet-rpc port  (default: discovered, needs a balance)
#   SIGNER           path to beldex-bridge-signer
#   SHARE_SUBDIR     outgoing share tree       (default: shares — do NOT point at shares-next)
set -euo pipefail

LOCAL="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL"

wrpc() {
  curl -s "http://127.0.0.1:$WPORT/json_rpc" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$1\",\"params\":$2}"
}
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);r=d.get('result');print(r['$1'] if r else 'ERR:'+json.dumps(d.get('error')))"; }

# Send a hand-over signed earlier with --sign-only.
submit_saved() {
  local SUB
  SUB=$(wrpc gateway_submit_descriptor_update \
    "{\"tx_metadata\":\"$METADATA\",\"signature\":\"$SIG\",\"signature_type\":\"eddsa\"}")
  echo "$SUB" | grep -q '"tx_hash"' || { echo "!! submit failed: $SUB" >&2; exit 1; }
  echo "   tx_hash : $(echo "$SUB" | jget tx_hash)"
}

MODE=full
case "${1:-}" in
  --sign-only) MODE=sign; SAVE="${3:-}"; shift
               [ -n "$SAVE" ] || { echo "usage: $0 --sign-only <new-Pgw-group-vk-hex> <file>" >&2; exit 1; } ;;
  --submit)    SAVED="${2:-}"
               [ -s "$SAVED" ] || { echo "usage: $0 --submit <file signed with --sign-only>" >&2; exit 1; }
               . "$SAVED"
               echo "== send the hand-over to $NEW_VK signed earlier (wallet on port $WPORT pays the fee)"
               submit_saved
               exit 0 ;;
esac

NEW_VK="${1:-}"
[ -n "$NEW_VK" ] || { echo "usage: $0 <new-Pgw-group-vk-hex>" >&2; exit 1; }
NEW_VK="${NEW_VK#0x}"
[ "${#NEW_VK}" -eq 64 ] || { echo "!! new owner key must be 64-char hex (got ${#NEW_VK})" >&2; exit 1; }

[ -f devnet-bridge.env ] && . ./devnet-bridge.env
GATEWAY_ID="${GATEWAY_ID:?set GATEWAY_ID or run bootstrap-bridge.sh first}"

# The handover pays an ordinary network fee from a funded wallet, with the change
# returning to it. There is no registration fee on an update — consensus charges that
# only on the register branch, which requires the gateway not to exist yet.
if [ -z "${WPORT:-}" ]; then
  for p in $(ls -d testdata/wallet-127.0.0.1-* 2>/dev/null | grep -v stderr | sed 's/.*-//' | sort -n); do
    BAL=$(curl -s "http://127.0.0.1:$p/json_rpc" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{"account_index":0}}' \
      | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("unlocked_balance",0))' 2>/dev/null || echo 0)
    [ "${BAL:-0}" -gt 1000000000 ] 2>/dev/null && { WPORT=$p; break; }
  done
fi
[ -n "${WPORT:-}" ] || { echo "!! no funded wallet-rpc found — mine more blocks first (./mine.sh 30)" >&2; exit 1; }

echo "== 1/3  build the descriptor update (wallet on port $WPORT pays the fee)"
# bridge_reserve is STICKY: consensus REJECTS an update that would clear it, so it is
# carried forward here unconditionally. A reserve gateway is the only kind this ceremony
# ever touches.
BUILD=$(wrpc gateway_update_descriptor "{\"gateway_id\":\"$GATEWAY_ID\",
  \"owner_key_type\":\"eddsa\",\"owner_key\":\"$NEW_VK\",
  \"bridge_reserve\":true,\"meta_info\":\"bridge reserve\",\"priority\":1}")
echo "$BUILD" | grep -q '"hash_to_sign"' || { echo "!! build failed: $BUILD" >&2; exit 1; }
DIGEST=$(echo "$BUILD"   | jget hash_to_sign)
METADATA=$(echo "$BUILD" | jget tx_metadata)
FEE=$(echo "$BUILD"      | jget fee)
echo "   digest : $DIGEST"
echo "   fee    : $FEE atomic units"

echo
echo "== 2/3  threshold-sign it with the OUTGOING Pgw (${SHARE_SUBDIR:-shares})"
# sign-pgw prints "Pgw signature : <128 hex>" and libsodium-verifies it before returning,
# so a wrong share tree fails here rather than as an opaque consensus rejection later.
# `pgw` is its own kind: sign-pevm.sh pins the leg per kind, so passing the leg through the
# environment was silently overridden and produced a Pevm signature over the wrong curve.
# Output is NOT discarded — when this failed, swallowing it left nothing to diagnose from.
./sign-pevm.sh pgw "0x$DIGEST" || {
  echo "!! the outgoing committee could not sign the hand-over." >&2
  echo "   The gateway still answers to the OLD key, so releases keep working; do not run" >&2
  echo "   the share promotion until this succeeds." >&2
  exit 1
}
# sign-pevm.sh logs under the kind name, inside testdata/.
SIG=$(grep -h 'Pgw signature' testdata/pgw-sign-*.log 2>/dev/null \
      | sed 's/.*: *//' | tr -d ' \r' | sort -u | head -1)
[ -n "$SIG" ] || { echo "!! no Pgw signature in testdata/pgw-sign-*.log" >&2; exit 1; }
[ "${#SIG}" -eq 128 ] || { echo "!! Pgw signature is ${#SIG} hex chars, expected 128" >&2; exit 1; }
echo "   signature : $SIG"

if [ "$MODE" = sign ]; then
  # Kept, not sent. The file authorises the gateway move to NEW_VK, so it is owner-only;
  # it is only ever sent once the rotation to that key is verified on chain.
  ( umask 077; printf 'NEW_VK=%s\nWPORT=%s\nMETADATA=%s\nSIG=%s\n' "$NEW_VK" "$WPORT" "$METADATA" "$SIG" > "$SAVE" )
  echo
  echo "hand-over signed and kept in $SAVE — send it with: $0 --submit $SAVE"
  echo "(keep the wallet on port $WPORT otherwise idle until then: spending the outputs it"
  echo " built this from would void it, and the outgoing key would have to sign again)"
  exit 0
fi

echo
echo "== 3/3  attach the signature and relay"
submit_saved

echo
echo "handover submitted — mine it in, then confirm the owner key moved:"
echo "  ./mine.sh 12 && ./commands/getblock.py >/dev/null"
echo "  curl -s http://127.0.0.1:\$DAEMON_RPC/json_rpc -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_gateway_info\",\"params\":{\"gateway_address\":\"$GATEWAY_ID\"}}'"

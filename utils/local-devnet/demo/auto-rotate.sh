#!/usr/bin/env bash
# auto-rotate.sh — rotate the bridge to a fresh key every epoch, unattended (devnet only).
#
# Started by demo-up.sh. Every POLL seconds it reads the height; once an epoch boundary has
# passed (and SETTLE blocks on top of it), it runs the whole rotation ceremony for the
# committee consensus just selected:
#
#   the new committee's key (made by `dkg-auto` on every member, which bootstrap leaves
#   running) → the outgoing key signs rotateSigner AND the gateway hand-over
#   → the incoming key signs the activation → propose, challenge window, activate → send the
#   hand-over → promote the shares → signers restart on the new key → signers send the ack.
#
# This is the devnet stand-in for what the signers will do themselves in production. It
# drives the existing rotate-ceremony.sh with CEREMONY_YES=1; nothing here signs or decides
# anything the ceremony does not already do. It always rotates to the newest committee: an
# epoch that passes mid-rotation is caught up by the next one.
#
# Failure handling:
#   * no key yet (dkg-auto retries a failed DKG within the epoch): the old key keeps serving;
#   * the new key fails its checks or probes (steps 1-2): it is moved aside, the old key keeps
#     serving, and dkg-auto's next attempt is tried in the same epoch;
#   * a later step fails: the ceremony is resumed from that step, again and again. After the
#     activation the bridge is mid-hand-over, so giving up is not an option — it keeps going.
set -uo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
cd "$LOCAL"

POLL="${POLL:-10}"
SETTLE="${SETTLE:-3}"                 # blocks past the boundary before acting
LAST_FILE="$STATE_DIR/last-rotated-epoch"
LOG="$STATE_DIR/rotations.log"        # one line per event, for status.sh
. "$STATE_DIR/demo.env"

event() { printf '%s  %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOG"; }

ceremony() {   # ceremony [--from N] — one ceremony run, its full output appended to the log
  CEREMONY_YES=1 SKIP_HANDOFF_PROOF=1 HANDOFF_BY_SIGNERS=1 MESH_PORT_BASE=7000 BRIDGE_DIR="$BC" WPORT="$MIKE_PORT" ROTATE_TIMELOCK=120 \
    ./rotate-ceremony.sh "$@" > "$STATE_DIR/ceremony-last.log" 2>&1
  local rc=$?
  cat "$STATE_DIR/ceremony-last.log" >> "$STATE_DIR/ceremony-all.log"
  return $rc
}

# Successor trees a failed DKG left behind. The ceremony REUSES any shares-next it finds when
# told "yes" to everything, so a stale or half-written tree must never be left in place.
set_aside_successor() {
  local d stamp; stamp=$(date +%Y%m%d-%H%M%S)
  for d in testdata/beldex-127.0.0.1-*/devnet/shares-next; do
    [ -d "$d" ] && mv "$d" "$d.failed-$stamp"
  done
  rm -f testdata/beldex-127.0.0.1-*/devnet/shares-next.lock
}

current_signer() { cast call "$WBDX" 'currentSigner()(address)' --rpc-url "$EVM_RPC" 2>/dev/null; }
# The key in shares-next, as its activation names it.
successor() {
  grep -oh '"pending_signer":"[0-9a-f]*"' testdata/beldex-127.0.0.1-*/devnet/shares-next/activation-* 2>/dev/null \
    | head -1 | sed 's/.*:"/0x/; s/"$//'
}
# The relayer sends the new committee's activation once the challenge window is over, so the
# contract can be on the new key before the ceremony's own step 5 gets there. What is left is
# the hand-over from step 6.
already_live() { [ -n "$(successor)" ] && [ "$(current_signer | tr 'A-Z' 'a-z')" = "$(successor)" ]; }
key_epoch()      { cast call "$WBDX" 'keyEpoch()(uint64)' --rpc-url "$EVM_RPC" 2>/dev/null; }

bridge_env
event "orchestrator started; last rotated epoch $(cat "$LAST_FILE")"

while true; do
  sleep "$POLL"
  H=$(height) || continue
  [ -n "$H" ] || continue
  E=$(( H / EPOCH_BLOCKS ))
  LAST=$(cat "$LAST_FILE" 2>/dev/null || echo 0)
  [ "$E" -gt "$LAST" ] || continue
  [ "$H" -ge $(( E * EPOCH_BLOCKS + SETTLE )) ] || continue

  # Only the key of the committee just selected: an older one in shares-next was never
  # installed, and the newest committee replaces it.
  KEY=$(./dkg-next.sh --check shares-next 2>/dev/null) || KEY=""
  case "$KEY" in
    "epoch $E "*) ;;
    *) [ "${WAITING:-}" = "$E" ] || event "epoch $E: waiting for the new committee's key (testdata/dkg-auto-*.log)"
       WAITING=$E
       continue ;;
  esac

  # And its activation: the new committee signs it right after the DKG, and it is the first
  # signature the key makes. Production rotates only to a key whose activation it has checked.
  if ! ls testdata/beldex-127.0.0.1-*/devnet/shares-next/activation-* >/dev/null 2>&1; then
    [ "${WAITING_ACT:-}" = "$E" ] || event "epoch $E: key ready, waiting for its activation (testdata/dkg-auto-*.log)"
    WAITING_ACT=$E
    continue
  fi

  MEMBERS=$(jrpc bridge_get_committee | jget "len(r.get('members',[]))" 2>/dev/null || echo "?")
  event "epoch $E (height $H): new committee of $MEMBERS — rotating from key epoch $(key_epoch)"
  T0=$(date +%s)

  START=()
  if already_live; then
    event "epoch $E: the new key is already live on chain (the relayer activated it) — finishing the hand-over from step 6"
    START=(--from 6)
  fi
  if ceremony "${START[@]}"; then
    echo "$E" > "$LAST_FILE"
    event "epoch $E: rotated in $(( $(date +%s) - T0 ))s — wBDX signer $(current_signer), key epoch $(key_epoch); gateway handed over; signers restarted"
    continue
  fi

  FROM=$(grep -oE 'rotate-ceremony\.sh --from [0-9]+' "$STATE_DIR/ceremony-last.log" | tail -1 | grep -oE '[0-9]+$')
  if [ "${FROM:-1}" -le 2 ]; then
    # The new key failed its checks or probes, and nothing moved on chain; the old key still
    # serves. dkg-auto makes another at its next attempt, in this epoch while there is time.
    set_aside_successor
    event "epoch $E: the new key failed step ${FROM:-1} ($(grep -m1 '!!' "$STATE_DIR/ceremony-last.log" | cut -c1-120)) — set aside, old key keeps serving, waiting for the next attempt"
    continue
  fi

  # Step 8 only PROVES the hand-off (the retired key is refused, the new one accepted). The
  # rotation itself is complete by then, so a failed proof is reported, not retried.
  if [ "$FROM" = "8" ]; then
    echo "$E" > "$LAST_FILE"
    event "epoch $E: rotated — wBDX signer $(current_signer), key epoch $(key_epoch); the step-8 proof did not complete (see .demo/ceremony-last.log)"
    continue
  fi

  # Past the DKG: finish this rotation before anything else.
  ATTEMPT=1
  while true; do
    event "epoch $E: step $FROM failed — resuming (attempt $ATTEMPT)"
    sleep 20
    if [ "$FROM" -le 5 ] && already_live; then
      event "epoch $E: the new key is already live on chain (the relayer activated it) — resuming from step 6"
      FROM=6
    fi
    if ceremony --from "$FROM"; then
      echo "$E" > "$LAST_FILE"
      event "epoch $E: rotation completed after resume — wBDX signer $(current_signer), key epoch $(key_epoch)"
      break
    fi
    NEXT=$(grep -oE 'rotate-ceremony\.sh --from [0-9]+' "$STATE_DIR/ceremony-last.log" | tail -1 | grep -oE '[0-9]+$')
    FROM="${NEXT:-$FROM}"
    if [ "$FROM" = "8" ]; then
      echo "$E" > "$LAST_FILE"
      event "epoch $E: rotated after resume — key epoch $(key_epoch); the step-8 proof did not complete"
      break
    fi
    ATTEMPT=$(( ATTEMPT + 1 ))
    [ "$ATTEMPT" -le 10 ] || { event "epoch $E: !! still failing at step $FROM after 10 attempts — needs a person (see .demo/ceremony-last.log)"; exit 1; }
  done
done

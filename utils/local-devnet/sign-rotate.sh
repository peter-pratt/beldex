#!/usr/bin/env bash
# sign-rotate.sh — have the OUTGOING committee threshold-sign an H.6 rotation.
#
#   runlog ./sign-rotate.sh 0x<preimage-from-03-rotate-prep.sh>
#
# The preimage is abi.encode(ROTATE_TAG, chainid, wBDX, newKeyEpoch, newSigner, nonce,
# deadline) — 7 words, 224 bytes. The nonce makes the authorization single-use and the
# deadline expires it. Signed by the key that is CURRENTLY in the contract, over its existing
# shares; that is what makes the hand-off self-authorizing rather than an admin action.
#
# ─── getting a successor key first ───────────────────────────────────────────────────
# cggmp21 0.6.3 has no threshold key refresh, so the incoming committee's key comes from
# a whole fresh DKG, run into a SEPARATE share tree so the outgoing key survives to sign
# this rotation:
#
#   runlog ./dkg-next.sh 1        # 1 = key generation; must not repeat one already used
#
# The DKG writes devnet/shares-next and prints the 33-byte group key — but NOT an Ethereum
# address, which is what 03-rotate-prep.sh needs. Get the address by having the incoming
# committee sign something throwaway; the signer derives and prints the address itself:
#
#   SHARE_SUBDIR=shares-next runlog ./sign-pevm.sh raw 0x<any 32 bytes>
#
# and read the `wBDX signer : 0x...` line. That doubles as a liveness check: if the new
# committee cannot produce a signature, do not rotate to it.
#
#   bridge-contract/devnet/03-rotate-prep.sh <that-address>
#
# Losing the outgoing shares before this signature exists means the contract can only be
# repointed by the admin break-glass — which is precisely the trust assumption H.6 exists
# to avoid.

# ─── two signatures, two directions (H.6.2b) ─────────────────────────────────────────
# A full hand-off needs TWO signatures over TWO preimages:
#
#   1. rotateSigner    — the OUTGOING committee (default `shares`) authorises the successor.
#                        Logs to rotate-sign-*.log.
#
#   2. activateRotation — the INCOMING committee (SHARE_SUBDIR=shares-next) proves it can
#                        already sign under the new key, so the contract will not retire the
#                        old key before the new one is live. Set ACTIVATE=1 to route this run
#                        to activate-sign-*.log (a distinct prefix) so 04-rotate.sh can tell
#                        the two signatures apart. Example:
#
#      SHARE_SUBDIR=shares-next ACTIVATE=1 runlog ./sign-rotate.sh 0x<ACTIVATE_PREIMAGE>

set -euo pipefail
if [ "${ACTIVATE:-0}" = "1" ]; then
  export LOG_PREFIX="${LOG_PREFIX:-activate}"
fi
exec "$(dirname "$0")/sign-pevm.sh" rotate "${1:-}"

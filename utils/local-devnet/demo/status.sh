#!/usr/bin/env bash
# status.sh — live bridge status for the demo, refreshed every few seconds.
#
#     ./demo/status.sh          # refresh every 5s (Ctrl-C to stop)
#     ./demo/status.sh once     # print once
DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "${1:-}" = "once" ]; then exec python3 "$DIR/status.py"; fi
while true; do
  OUT=$(python3 "$DIR/status.py" 2>&1)
  clear
  printf '%s\n' "$OUT"
  sleep "${REFRESH:-5}"
done

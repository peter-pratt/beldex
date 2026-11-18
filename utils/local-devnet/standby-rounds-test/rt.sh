#!/usr/bin/env bash
# rt.sh <command> — test kit for standby rounds on the local devnet. See README.md for the order.
#
#   build | unit | stop | devnet | devnet-wait | bootstrap | start | status
#   first | committee | drills | takeover (ends with redeem) | redeem | collect
#
# Every command prints a short report and also saves it to out/<command>.out.
set -uo pipefail

# Fixed on purpose: a BC or REPO already in the shell (a ~/.bashrc export, say) would point the
# kit at some other checkout. By default the kit tests the beldex checkout it lives in, with
# bridge-contract checked out beside it. Override only with RT_BC / RT_REPO.
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${RT_REPO:-$(cd "$KIT/../../.." && pwd)}"
export BC="${RT_BC:-$(cd "$REPO/.." && pwd)/bridge-contract}"
OUT="$KIT/out"; mkdir -p "$OUT"
LOG="$OUT/stamped.log"            # every signer's log in one file, each line stamped with time and node
SNAP="$OUT/standby-snapshots.jsonl" # bridge_get_standby, every change (rounds are only visible while open)
touch "$LOG" "$SNAP"
# jr height standby evm_standby envb wport deposit reserves start_live start_standby holders; $L $S $EVM $ADMIN_KEY $TO
. "$REPO/utils/local-devnet/standby-e2e-env.sh" >/dev/null
K1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d   # anvil account #1, holds the minted wBDX ($TO)
W=10                                                                     # devnet round window

say() { echo "$(date +%T) h=$(height 2>/dev/null || echo ?) $*"; }
st() { jr bridge_get_standby | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)"; }
port_of() { tr '\0' '\n' < /proc/$1/environ 2>/dev/null | sed -n 's#^BRIDGE_SIGNER_BELDEXD_RPC_URL=.*:##p'; }
role_of() { tr '\0' '\n' < /proc/$1/environ 2>/dev/null | grep -aqx 'BRIDGE_SIGNER_ROLE=standby' && echo standby || echo live; }
signers() { for p in $(pgrep -f 'beldex-bridge-signer [s]erve'); do echo "$(port_of $p) $(role_of $p) $p"; done | sort; }
pid_of() { signers | awk -v x="$1" -v r="$2" '$1==x && $2==r{print $3}'; }
ports() { ls -d "$L"/testdata/beldex-127.0.0.1-*/ 2>/dev/null | sed -E 's#.*-([0-9]+)/$#\1#'; }
lines() { wc -l < "$LOG"; }
# Bob's Beldex address, asked of his wallet RPC (its port is in the devnet log).
bob_addr() { local p; p=$(grep -aoE 'Started RPC Wallet - Bob, on 127.0.0.1:[0-9]+' "$S/devnet.log" | tail -1 | sed 's/.*://')
  [ -n "$p" ] && curl -s "http://127.0.0.1:$p/json_rpc" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["address"])' 2>/dev/null; }
# The first line matching $2 in the stamped log after line $1, waiting up to $3 seconds.
next_line() { local end=$(( $(date +%s) + ${3:-3600} )) l
  while [ "$(date +%s)" -lt $end ]; do
    l=$(tail -n +$(($1+1)) "$LOG" | grep -a -m1 -E "$2"); [ -n "$l" ] && { echo "$l"; return 0; }; sleep 1
  done; return 1; }
# Wait up to $1 seconds for the python condition $2 over r (bridge_get_standby); prints changes of $3.
wait_for() { local end=$(( $(date +%s) + $1 )) last="" now
  while [ "$(date +%s)" -lt $end ]; do
    now=$(st "$3" 2>/dev/null); [ "$now" != "$last" ] && { say "  $now"; last="$now"; }
    [ "$(st "$2" 2>/dev/null)" = True ] && return 0; sleep 10
  done; return 1; }
contract() { envb; cast call "$WBDX" "$1" --rpc-url "$EVM" 2>/dev/null | awk '{print $1}'; }
# The EVM address attested with gateway key $1 (prefix is enough).
pevm_of() { jr bridge_get_standby | python3 -c "
import sys,json;r=json.load(sys.stdin)['result']
print(next(('0x'+a['pevm_address']).lower() for a in r['attestations'] if a['pgw_vk'].startswith('$1')))" 2>/dev/null; }
lc() { tr 'A-Z' 'a-z'; }

cmd="${1:-}"; shift || true
# A fresh devnet starts a fresh record: the outputs of an earlier run are kept in old/.
if [ "$cmd" = devnet ] && [ -s "$LOG" ] && [ "$(pgrep -fc 'bin/[b]eldexd')" = 0 ]; then
  mkdir -p "$KIT/old"; mv "$OUT" "$KIT/old/out-$(date +%m%d-%H%M)"; mkdir -p "$OUT"; touch "$LOG" "$SNAP"
fi
exec > >(tee "$OUT/${cmd:-help}.out") 2>&1

case "$cmd" in

build)
  say "HEAD $(git -C "$REPO" log -1 --format='%h %s')  branch $(git -C "$REPO" branch --show-current)"
  say "git status: $(git -C "$REPO" status --porcelain | wc -l) changed file(s)"
  say "building beldexd, wallet-rpc and unit tests (build/test-validation)…"
  # A failed build must not pass for a stale binary: print the errors and stop.
  failed=0
  cmake --build "$REPO/build/test-validation" -j"$(nproc)" --target daemon wallet_rpc_server unit_tests > "$OUT/build-cpp.log" 2>&1 \
    || { grep -E 'error|Error' "$OUT/build-cpp.log" | head -20; failed=1; }
  tail -2 "$OUT/build-cpp.log"
  say "building the signer (serve-live)…"
  (cd "$REPO/bridge/signer" && cargo build --features serve-live > "$OUT/build-signer.log" 2>&1) \
    || { grep -A12 '^error' "$OUT/build-signer.log" | head -40; failed=1; }
  tail -1 "$OUT/build-signer.log"
  say "building the relayer (submit-http)…"
  (cd "$REPO/bridge/relayer" && cargo build --features submit-http > "$OUT/build-relayer.log" 2>&1) \
    || { grep -A12 '^error' "$OUT/build-relayer.log" | head -40; failed=1; }
  tail -1 "$OUT/build-relayer.log"
  [ "$failed" = 0 ] || { say "!! BUILD FAILED: the binaries below are older than the code"; }
  ls -la --time-style=+%F_%T "$REPO/build/test-validation/bin/beldexd" "$REPO/build/test-validation/bin/beldex-wallet-rpc" \
    "$REPO/build/test-validation/tests/unit_tests/unit_tests" "$REPO/bridge/signer/target/debug/beldex-bridge-signer" \
    "$REPO/bridge/relayer/target/debug/beldex-bridge-relayer" | awk '{print $6, $7}'
  [ "$failed" = 0 ] || exit 1
  ;;

unit)
  say "C++: standby rounds and key attestation"
  "$REPO/build/test-validation/tests/unit_tests/unit_tests" --gtest_filter='GatewayStandbyRounds.*:GatewayBridgeKeyAttestation.*' 2>&1 \
    | grep -E '^\[ +(PASSED|FAILED) |^\[==========\] [0-9]+ tests'
  say "C++: every gateway and bridge test (regressions)"
  "$REPO/build/test-validation/tests/unit_tests/unit_tests" --gtest_filter='Gateway*:*Bridge*:*bridge*' 2>&1 \
    | grep -E '^\[ +(PASSED|FAILED) |^\[==========\] [0-9]+ tests'
  say "signer: default library tests"
  (cd "$REPO/bridge/signer" && cargo test --lib 2>&1 | grep -E '^test result|FAILED|panicked')
  say "signer: all features (about 10 minutes)"
  (cd "$REPO/bridge/signer" && cargo test --all-features --lib 2>&1 | grep -E '^test result|FAILED|panicked')
  ;;

stop)
  pkill -f 'stamp-log[s].py|snap.p[y]' 2>/dev/null
  pkill -f 'beldex-bridge-signer [s]erve'; pkill -f 'beldex-bridge-signer [d]kg-auto'; pkill -f 'serve-live.s[h]'; pkill -f 'mine.sh [l]oop'
  pkill -INT -f 'master_node_network.p[y]'; sleep 3
  pkill -f '[b]eldex-wallet-rpc'; pkill -f 'bin/[b]eldexd'; pkill -f '[a]nvil'; pkill -f 'sleep [i]nfinity'
  sleep 5
  left=$(pgrep -af '[b]eldexd|[a]nvil|master_node_networ[k]|[b]eldex-bridge-signer|[b]eldex-wallet-rpc' | wc -l)
  say "stopped; processes left: $left"
  ;;

devnet)
  [ "$(pgrep -fc 'bin/[b]eldexd')" = 0 ] || { echo "!! a devnet is running: ./rt.sh stop first"; exit 1; }
  # The relayer's state belongs to the old anvil chain (nonces, pending relays).
  [ -d "$S/relayer-state" ] && mv "$S/relayer-state" "$S/relayer-state.old-$(date +%s)"
  rm -f "$OUT/bootstrap.ok"
  cd "$L" && BELDEX_BIN="$REPO/build/test-validation/bin" DEVNET_MNS=21 DEVNET_BRIDGE_SEATS=14 \
    nohup bash -c "sleep infinity | python3 -u master_node_network.py --fresh > $S/devnet.log 2>&1" >/dev/null 2>&1 &
  sleep 5; say "fresh devnet starting: 21 master nodes, 14 bridge seats; log $S/devnet.log"
  say "next: ./rt.sh devnet-wait   (takes about 3 to 4 hours)"
  ;;

devnet-wait)
  start=$(date +%s)
  until grep -q 'Use Ctrl-C to exit' "$S/devnet.log" 2>/dev/null; do
    [ "$(pgrep -fc 'master_node_networ[k]')" = 0 ] && { echo "!! the harness exited:"; grep -aE 'Error|error|Traceback' "$S/devnet.log" | tail -5; exit 1; }
    mins=$(( ($(date +%s) - start) / 60 ))
    [ $((mins % 10)) = 0 ] && say "waiting (${mins} min): $(sed 's/\x1b\[[0-9;]*m//g' "$S/devnet.log" | grep -avE '^\s*$|^20[0-9]{2}-[0-9]{2}-[0-9]{2} ' | tail -1 | cut -c1-110)"
    sleep 60
  done
  say "devnet ready"
  sed 's/\x1b\[[0-9;]*m//g' "$S/devnet.log" | grep -aE 'Bridge seats|Bridge committee|has new wallet' | cut -c1-140
  ;;

bootstrap)
  rm -f "$OUT/bootstrap.ok"
  say "bridge-contract: $BC ($(git -C "$BC" branch --show-current) $(git -C "$BC" log -1 --format=%h))"
  # The same signer build as every other step (bootstrap-bridge.sh would otherwise look for a
  # release build to check the first key's certificate).
  (cd "$L" && BC="$BC" SIGNER="$REPO/bridge/signer/target/debug/beldex-bridge-signer" ./bootstrap-bridge.sh) \
    > "$OUT/bootstrap-full.log" 2>&1; rc=$?
  sed 's/\x1b\[[0-9;]*m//g' "$OUT/bootstrap-full.log" | grep -aE '^== |WBDX=|PEVM_ADDR=|GATEWAY_ID=|serving|!!|rror' | cut -c1-150
  say "bootstrap exit code $rc"
  [ "$rc" = 0 ] && touch "$OUT/bootstrap.ok" || { echo "!! bootstrap failed: the last lines of out/bootstrap-full.log:"; tail -5 "$OUT/bootstrap-full.log"; exit "$rc"; }
  ;;

start)
  [ -f "$OUT/bootstrap.ok" ] || { echo "!! bootstrap has not succeeded on this devnet: run ./rt.sh bootstrap"; exit 1; }
  envb; [ -n "${GATEWAY_ID:-}" ] || { echo "!! no devnet-bridge.env: run ./rt.sh bootstrap"; exit 1; }
  export BRIDGE_SIGNER_SIGN_TIMEOUT_SECS=120
  say "live signers on every node (supervised)"; (start_live)
  say "standby signers on every node (supervised)"; (start_standby)
  pkill -f 'stamp-log[s].py|snap.p[y]' 2>/dev/null
  nohup python3 "$KIT/stamp-logs.py" "$LOG" "$L/testdata" >/dev/null 2>&1 &
  nohup python3 "$KIT/snap.py" "$SNAP" >/dev/null 2>&1 &
  sleep 5
  [ -n "$(signers)" ] || { say "!! no signer is running; see $L/testdata/*/bridge-signer*.log"; exit 1; }
  say "signers: $(signers | awk '{print $2}' | sort | uniq -c | xargs)"
  say "DKG timeout $(tr '\0' '\n' < /proc/$(pid_of "$(ports | head -1)" standby)/environ | grep -a DKG_TIMEOUT)"
  ;;

status)
  envb
  say "$(standby)"
  echo "         contract: signer $(contract 'currentSigner()(address)') standby $(contract 'standbySigner()(address)') keyEpoch $(contract 'keyEpoch()(uint64)')"
  jr bridge_get_standby | python3 -c '
import sys,json; r=json.load(sys.stdin)["result"]
print("         waiting:", (r.get("waiting_key") or "-")[:12], "| open rounds (start, end, checked in/drawn):", [(x["round_height"], x["window_end"], "%d/%d" % (len(x.get("checked_in", [])), len(x["members"]))) for x in r.get("standby_rounds", [])], "| drawn last:", len(r.get("standby_missed_checkins", [])))'
  echo "         signers: $(signers | awk '{print $2}' | sort | uniq -c | xargs) | holders with a standby set: $(holders | awk -F'standby:' '$2>0' | wc -l)"
  ;;

first)
  [ -n "$(signers)" ] || { echo "!! no signer is running: run ./rt.sh start first"; exit 1; }
  say "waiting (up to 45 min) for the first standby to be named on the gateway and on the contract"
  wait_for 2700 'bool(r.get("standby_key")) and not r.get("standby_stale")' \
    '"owner",(r.get("owner_key") or "-")[:8],"standby",(r.get("standby_key") or "-")[:8],"waiting",(r.get("waiting_key") or "-")[:8],"rounds",[x["round_height"] for x in r.get("standby_rounds",[])]' \
    || { say "!! TIMEOUT: no standby named on the gateway"; exit 1; }
  key=$(st 'r["standby_key"][:12]')
  for _ in $(seq 1 60); do [ "$(contract 'standbySigner()(address)' | lc)" = "$(pevm_of "$key")" ] && break; sleep 10; done
  cs=$(contract 'standbySigner()(address)' | lc); want=$(pevm_of "$key")
  say "gateway standby $key, attested EVM address $want, contract standby $cs → $([ "$cs" = "$want" ] && echo MATCH || echo MISMATCH)"
  say "events:"
  grep -aE 'checked in as member|NO STANDBY: .*generating|standby key generated|key attestation \(|naming the newest attested key' "$LOG" \
    | awk '{k=$3" "$4" "$5; if(!s[k]++) print}' | cut -c1-150 | head -12
  echo "         round members that generated: $(grep -ac 'standby key generated' "$LOG")  attestations sent: $(grep -ac 'key attestation (' "$LOG")"
  ;;

committee)
  # Each round's members as consensus reports them (RPC) against the nodes that found themselves
  # on its committee through bridge.committee (OMQ) and started, or found they were not.
  for p in $(ports); do echo "$p $(jr get_master_node_key '{}' "$p" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("result",{}).get("master_node_pubkey",""))' 2>/dev/null)"; done > "$OUT/mn-keys.txt"   # a node that is not a master node has no key
  python3 - "$SNAP" "$OUT/mn-keys.txt" "$LOG" <<'EOF'
import json, re, sys
snap, keys, log = sys.argv[1:4]
port = {k: p for p, k in (l.split() for l in open(keys) if len(l.split()) == 2)}
rounds = {}
for l in open(snap):
    for x in json.loads(l)["r"].get("standby_rounds", []):
        rounds[x["round_height"]] = sorted(port.get(m, "?" + m[:8]) for m in x["members"])
joined, outside = {}, {}
for l in open(log, errors="replace"):
    m = re.match(r"\S+ S(\d+) NO STANDBY: .*generating .* round (\d+)$", l)
    if m: joined.setdefault(int(m[2]), set()).add(m[1])
    m = re.match(r"\S+ S(\d+)\s+standby round (\d+): this node is not on its committee", l)
    if m: outside.setdefault(int(m[2]), set()).add(m[1])
bad = 0
for h in sorted(rounds):
    mem = set(rounds[h]); j = joined.get(h, set()); o = outside.get(h, set())
    wrong_in, wrong_out = j - mem, o & mem
    ok = not wrong_in and not wrong_out
    bad += not ok
    print(f"round {h}: members {' '.join(sorted(mem))} | started {len(j)} | said not a member {len(o)} | "
          + ("OK" if ok else f"WRONG: started but not a member {sorted(wrong_in)}, members told no {sorted(wrong_out)}"))
print(f"{len(rounds)} round(s) checked, {bad} wrong")
EOF
  ;;

drills)
  # A: a dead standby goes stale and is replaced. B: one member of the next round is paused mid key
  # generation (killed DKG). C: in a later round every member is held past the window (late
  # attestation). D: a replacement is named on both chains.
  envb
  old=$(st 'r.get("standby_key") or ""'); [ -n "$old" ] || { echo "!! no named standby: run ./rt.sh first"; exit 1; }
  holders_now=$(holders | awk -F'[ :]' '$5>0{print $1}')
  pick=$(echo "$holders_now" | head -3 | xargs)
  pids=""; for p in $pick; do pids="$pids $(pid_of "$p" standby)"; done
  mark=$(lines)
  kill -STOP $pids; say "A: standby ${old:0:12}: paused the standby signers of 3 of its holders ($pick), pids$pids"
  seen=$(st 'r.get("standby_last_seen_height")')
  say "A: last proof at h$seen; stale expected at h$((seen + 120)) (about an hour)"
  wait_for 10800 'bool(r.get("standby_stale"))' '"stale",r.get("standby_stale"),"seen",r.get("standby_last_seen_height")' \
    || { kill -CONT $pids; say "!! TIMEOUT: the standby never went stale"; exit 1; }
  say "A: STALE at h$(height) (last seen h$(st 'r.get("standby_last_seen_height")'))"
  smark=$(lines)
  end=$(( $(date +%s) + 600 ))
  until [ "$(tail -n +$((smark+1)) "$LOG" | grep -ac 'Archived this standby set')" -ge 3 ] || [ "$(date +%s)" -gt $end ]; do sleep 2; done
  say "A: the running holders stepped aside: $(tail -n +$((smark+1)) "$LOG" | grep -a 'Archived this standby set' | awk '{print $2}' | xargs)"
  kill -CONT $pids; say "A: resumed the paused holders"

  l=$(next_line "$mark" 'S[0-9]+ NO STANDBY: .*generating the next standby key with the committee of standby round' 1800) \
    || { say "!! TIMEOUT: no round started after the stale point"; exit 1; }
  port=$(echo "$l" | awk '{print $2}' | tr -d S); R1=$(echo "$l" | grep -oE '[0-9]+$')
  say "B: round $R1 started (first seen on $port) — pausing that member 10 s in, for 270 s"
  sleep 10; p=$(pid_of "$port" standby); kill -STOP "$p"; say "B: paused standby $port (pid $p)"
  sleep 270; kill -CONT "$p"; say "B: resumed standby $port"
  say "B: round $R1 outcome:"
  grep -aE "round $R1\$" "$LOG" | awk '{print $2}' | sort -u | xargs echo "         members that started:"
  awk -v m="$(grep -an "round $R1\$" "$LOG" | head -1 | cut -d: -f1)" 'NR>m' "$LOG" \
    | grep -aE 'standby key generation failed|standby key generated' | head -8 | cut -c1-140

  # C: the first later round in which members generate a key; hold them all past its window.
  r1line=$(grep -an "round $R1\$" "$LOG" | head -1 | cut -d: -f1)
  after=$R1; done_c=""
  while [ -z "$done_c" ]; do
    l=$(next_line "$r1line" "S[0-9]+ NO STANDBY: .*generating .* round ($(seq $((after+10)) 10 $((after+400)) | xargs | tr ' ' '|'))\$" 3600) \
      || { say "!! TIMEOUT: no later round started"; exit 1; }
    R2=$(echo "$l" | grep -oE '[0-9]+$'); after=$R2
    rm_=$(grep -an "round $R2\$" "$LOG" | head -1 | cut -d: -f1)
    say "C: round $R2 started"; sleep 30
    members=$(grep -aE "S[0-9]+ NO STANDBY: .* round $R2\$" "$LOG" | awk '{print $2}' | tr -d S | sort -u | xargs)
    say "C: round $R2 members that started: $members"
    held=""; left="$members"; end=$(( $(date +%s) + 600 ))
    while [ -n "$left" ] && [ "$(date +%s)" -lt $end ]; do
      rest=""
      for m in $left; do
        # this member's outcome in R2 only: a failure of the previous round can be logged after R2 began
        ms=$(grep -anE "S$m NO STANDBY: .* round $R2\$" "$LOG" | head -1 | cut -d: -f1)
        l=$(tail -n +$((ms+1)) "$LOG" | grep -a -m1 -E "S$m (standby key generated|  standby key generation failed)")
        case "$l" in
          "") rest="$rest $m" ;;
          *failed*) say "C: member $m failed its key generation: ${l:0:120}" ;;
          *) pp=$(pid_of "$m" standby); kill -STOP "$pp"; held="$held $pp"; say "C: held member $m right after its key was generated" ;;
        esac
      done
      left=$(echo $rest); [ -n "$left" ] && sleep 1
    done
    if [ -z "$held" ]; then say "C: round $R2 produced no key; trying the next round"; continue; fi
    until [ "$(height)" -gt $((R2 + W + 1)) ]; do sleep 10; done
    kill -CONT $held; say "C: round $R2's window closed at h$((R2 + W)); released the members at h$(height)"
    sleep 150
    say "C: refused attestations: $(tail -n +$((rm_+1)) "$LOG" | grep -a "standby round $R2 does not take attestations" | awk '{print $2}' | sort -u | wc -l) member(s)  | waiting key now: $(st '(r.get("waiting_key") or "-")[:12]')"
    say "C: sets that stepped aside because the round closed: $(tail -n +$((rm_+1)) "$LOG" | grep -a "standby round $R2 closed without attesting this key" | awk '{print $2}' | sort -u | xargs)"
    tail -n +$((rm_+1)) "$LOG" | grep -aE "does not take attestations|closed without attesting" | head -4 | cut -c1-160
    done_c=1
  done

  # D also takes one idle standby signer offline before the replacement rounds: a round that
  # draws it must still generate its key with the members that checked in, and remember it.
  victim=${members%% *}; vpid=$(pid_of "$victim" standby)
  vkey=$(jr get_master_node_key '{}' "$victim" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["master_node_pubkey"])')
  snap0=$(wc -l < "$SNAP")
  kill -STOP "$vpid"; say "D: paused the idle standby signer of $victim (pid $vpid) before the replacement rounds"
  say "D: waiting (up to 45 min) for a replacement named on both chains"
  wait_for 2700 "bool(r.get('standby_key')) and not r.get('standby_stale') and r.get('standby_key')!='$old'" \
    '"standby",(r.get("standby_key") or "-")[:8],"stale",r.get("standby_stale"),"waiting",(r.get("waiting_key") or "-")[:8],"rounds",[x["round_height"] for x in r.get("standby_rounds",[])]' \
    || { say "!! TIMEOUT: no replacement named"; exit 1; }
  key=$(st 'r["standby_key"][:12]')
  for _ in $(seq 1 60); do [ "$(contract 'standbySigner()(address)' | lc)" = "$(pevm_of "$key")" ] && break; sleep 10; done
  cs=$(contract 'standbySigner()(address)' | lc); want=$(pevm_of "$key")
  say "D: new standby $key; contract standby $cs → $([ "$cs" = "$want" ] && echo MATCH || echo MISMATCH)"
  # Which round made it, who was drawn and who checked in, and whether the paused one is remembered.
  # The heredoc is python's stdin (the script), so the gateway answer goes through a file.
  jr bridge_get_standby > "$OUT/d-standby.json"
  python3 - "$SNAP" "$snap0" "$vkey" "$victim" "$OUT/d-standby.json" <<'PY'
import json, sys
snap, start, victim, port = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
r = json.load(open(sys.argv[5]))["result"]
rounds = {}
for i, l in enumerate(open(snap)):
    if i < start:
        continue
    for x in json.loads(l)["r"].get("standby_rounds", []):
        rounds[x["round_height"]] = x
key_round = next((a["round_height"] for a in r.get("attestations", []) if a["pgw_vk"] == r.get("standby_key")), None)
for h in sorted(rounds):
    x = rounds[h]
    drawn = victim in x["members"]
    print("         round %d: %d of %d checked in%s%s" % (h, len(x.get("checked_in", [])), len(x["members"]),
          "; drew the paused %s, which did not check in" % port if drawn and victim not in x.get("checked_in", []) else "",
          "  <- made the new standby" if h == key_round else ""))
missed = [m for m in r.get("standby_missed_checkins", []) if m["master_node"] == victim]
made = rounds.get(key_round)
if made and victim in made["members"] and victim not in made.get("checked_in", []):
    print("         D: CHECK-IN PASS: round %d drew the paused node and still made the key with %d of %d members"
          % (key_round, len(made["checked_in"]), len(made["members"])))
elif any(victim in x["members"] for x in rounds.values()):
    print("         D: the paused node was drawn, but the key came from a round without it (round %s)" % key_round)
else:
    print("         D: inconclusive: no round drew the paused node; rerun the drills")
print("         D: the paused node is %s" % ("drawn last (missed its check-in at %s)" % [m["round_height"] for m in missed] if missed else "NOT on the drawn-last list"))
PY
  kill -CONT "$vpid"; say "D: resumed $victim"
  ;;

takeover)
  # The owner's signers stop (3 of 6 killed: below the threshold of 4); a deposit goes unminted;
  # the standby takes over on both chains, mints it, releases a redeem, and gets a standby of its own.
  envb
  owner=$(st 'r["owner_key"]'); sb=$(st 'r.get("standby_key") or ""')
  [ -n "$sb" ] && [ "$(st 'r.get("standby_stale")')" = False ] || { echo "!! no working standby: run ./rt.sh first or wait for one"; exit 1; }
  sb_evm=$(pevm_of "${sb:0:12}")
  bob=$(bob_addr); [ -n "$bob" ] || { echo "!! could not read Bob's address from his wallet RPC"; exit 1; }
  supply0=$(contract 'totalSupply()(uint256)'); res0=$(reserves | awk '/gateway_balance/{print $2}')
  say "owner ${owner:0:12}, standby ${sb:0:12} (EVM $sb_evm); supply $supply0, reserve $res0"
  cast send "$WBDX" 'setStandbyTakeoverDelay(uint256)' 60 --private-key "$ADMIN_KEY" --rpc-url "$EVM" >/dev/null \
    && say "contract takeover delay set to 60 s (default 1 hour) to keep the test short"
  victims=$(holders | awk -F'[ :]' '$3>0 && $5==0{print $1}' | head -3 | xargs)
  [ "$(echo $victims | wc -w)" = 3 ] || victims=$(holders | awk -F'[ :]' '$3>0{print $1}' | head -3 | xargs)
  for p in $victims; do kill "$(pid_of "$p" live)"; done
  T0=$(date +%s); say "killed the live signers of $victims: the owner key is down to 3 of 6"
  deposit 10; say "deposited 10 BDX to the gateway (it cannot be minted by the owner now)"
  say "waiting (up to 2 h) for the standby to become the owner on both chains"
  end=$(( $(date +%s) + 7200 )); last=""
  while [ "$(date +%s)" -lt $end ]; do
    o=$(st 'r["owner_key"][:12]'); c=$(contract 'currentSigner()(address)' | lc)
    now="gateway owner $o, contract signer $c"; [ "$now" != "$last" ] && { say "  $now"; last="$now"; }
    [ "$o" = "${sb:0:12}" ] && [ "$c" = "$sb_evm" ] && break; sleep 15
  done
  [ "$o" = "${sb:0:12}" ] && [ "$c" = "$sb_evm" ] || { say "!! TIMEOUT: takeover not complete"; exit 1; }
  say "TAKEOVER complete on both chains, $(( ($(date +%s) - T0) / 60 )) min after the kill"
  grep -aE 'TAKEOVER (BEGIN|COMPLETE) submitted|takeover_(begin|complete) relayed: relayed' "$LOG" | tail -4 | cut -c1-120
  say "waiting (up to 40 min) for the deposit to be minted by the new owner"
  end=$(( $(date +%s) + 2400 ))
  until [ "$(contract 'totalSupply()(uint256)')" != "$supply0" ] || [ "$(date +%s)" -gt $end ]; do sleep 15; done
  supply1=$(contract 'totalSupply()(uint256)'); say "supply $supply0 → $supply1"
  "$0" redeem
  ;;

redeem)
  # After the takeover: the new owner releases a redeem, and gets a standby of its own.
  envb
  bob=$(bob_addr); [ -n "$bob" ] || { echo "!! could not read Bob's address from his wallet RPC"; exit 1; }
  owner=$(st 'r["owner_key"]')
  res1=$(reserves | awk '/gateway_balance/{print $2}'); supply1=$(contract 'totalSupply()(uint256)')
  say "owner ${owner:0:12}; supply $supply1, reserve $res1"
  cast send "$WBDX" 'redeemToNative(uint256,string)' 5000000000 "$bob" --private-key "$K1" --rpc-url "$EVM" >/dev/null \
    || { say "!! the redeem was not accepted"; exit 1; }
  say "redeemed 5 wBDX to Bob (${bob:0:12}…); waiting (up to 45 min: anvil finality is 64 blocks) for the release"
  end=$(( $(date +%s) + 2700 ))
  until [ "$(reserves | awk '/gateway_balance/{print $2}')" != "$res1" ] || [ "$(date +%s)" -gt $end ]; do sleep 15; done
  res2=$(reserves | awk '/gateway_balance/{print $2}'); supply2=$(contract 'totalSupply()(uint256)')
  [ "$res2" != "$res1" ] || { say "!! TIMEOUT: no release"; exit 1; }
  say "reserve $res1 → $res2, supply $supply1 → $supply2 → $([ "$res2" = "$supply2" ] && echo 'reserve = supply' || echo 'reserve ≠ supply')"
  grep -aE 'release.*(signed|relayed|submitted)' "$LOG" | tail -2 | cut -c1-140
  say "waiting (up to 45 min) for a standby for the new owner"
  wait_for 2700 "bool(r.get('standby_key')) and not r.get('standby_stale') and r.get('standby_key') != r.get('owner_key')" \
    '"owner",r["owner_key"][:8],"standby",(r.get("standby_key") or "-")[:8],"rounds",[x["round_height"] for x in r.get("standby_rounds",[])]' \
    || { say "!! TIMEOUT: no standby for the new owner"; exit 1; }
  key=$(st 'r["standby_key"][:12]')
  for _ in $(seq 1 60); do [ "$(contract 'standbySigner()(address)' | lc)" = "$(pevm_of "$key")" ] && break; sleep 10; done
  cs=$(contract 'standbySigner()(address)' | lc)
  say "new owner's standby $key; contract standby $cs → $([ "$cs" = "$(pevm_of "$key")" ] && echo MATCH || echo MISMATCH)"
  ;;

collect)
  say "HEAD $(git -C "$REPO" log -1 --format='%h %s')"
  "$0" status 2>&1 | tail -n +1
  echo "--- events in the signer logs"
  for pat in 'checked in as member' 'too few to generate a key' 'check-in did not land' 'NO STANDBY:' 'standby key generated' 'standby key generation failed' 'key attestation (' \
             'does not take attestations' 'key attested:' 'naming the newest attested key' 'Archived this standby set' \
             'TAKEOVER BEGIN submitted' 'TAKEOVER COMPLETE submitted' 'panicked at'; do
    printf '  %-36s %s\n' "$pat" "$(grep -acF "$pat" "$LOG")"; done
  echo "--- why key generation failed (count, reason)"
  grep -aoE 'standby key generation failed \([^)]{0,60}' "$LOG" | sed -E 's/.*failed \(//; s/[0-9]{4,}/N/g' | sort | uniq -c | sort -rn | head -6
  echo "--- why sets stepped aside"
  grep -aoE 'serve: [^.]{0,90}\. Archived' "$LOG" | sed -E 's/serve: //; s/\. Archived//; s/[0-9]{3,}/N/g' | sort | uniq -c | sort -rn | head -6
  echo "--- '!!' lines (distinct, numbers folded)"
  grep -aE ' !! ' "$LOG" | cut -d' ' -f3- | sed -E 's/[0-9a-f]{8,}/X/g; s/[0-9]+/N/g' | sort | uniq -c | sort -rn | head -10 | cut -c1-160
  ;;

*) sed -n '2,7p' "$0" ;;
esac

#!/usr/bin/env python3
"""topup-fee-wallets.py — keep every bridge seat's fee wallet funded from a treasury wallet.

Each seat's signer (beldex-bridge-serve@<seat>) reports its fee wallet on its status endpoint:
`fee_wallet_balance` and `fee_wallet_address` on /status, `fee_wallet_low` on /health. This
script reads every seat's status and sends a fixed top-up from the treasury wallet to each one
that is low. Run it on the ops machine, from cron or a systemd timer (e.g. every 30 minutes).

    topup-fee-wallets.py seats.txt                  # show what it would send (default)
    topup-fee-wallets.py seats.txt --send           # send

seats.txt: one seat per line, `<seat> <status URL>`, e.g.
    seat01 http://10.0.0.11:9100
(# starts a comment). The status port listens on 127.0.0.1 by default: reach it over your
monitoring network or an SSH tunnel, never the public internet.

Settings (environment):
    TREASURY_WALLET_RPC         http://127.0.0.1:19095/json_rpc  (beldex-wallet-rpc --rpc-login)
    TREASURY_WALLET_LOGIN_FILE  its user:password, mode 600
    TOPUP_BELOW_BDX             top up a seat whose balance is below this (default 5)
    TOPUP_AMOUNT_BDX            how much to send each time (default 20)
    TOPUP_MAX_PER_DAY           at most this many top-ups per seat per day (default 2)
    TOPUP_STATE_FILE            where it remembers what it sent (default ./topup-state.json)

A seat is only ever paid at the address it reports itself, at most TOPUP_MAX_PER_DAY times a
day, so a wrong or tampered status costs at most that much.
"""
import base64
import datetime
import json
import os
import stat
import sys
import urllib.request

ATOMIC = 1_000_000_000  # 1 BDX


def env_float(name, default):
    v = os.environ.get(name, "").strip()
    return float(v) if v else default


def read_login(path):
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        sys.exit(f"!! {path} is readable by others: chmod 600 it")
    text = open(path).read().strip()
    if ":" not in text or "\n" in text:
        sys.exit(f"!! {path} must hold one line, user:password")
    return text


def http_json(url, payload=None, login=None, timeout=10):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if login:
        req.add_header("Authorization", "Basic " + base64.b64encode(login.encode()).decode())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def wallet(url, login, method, params):
    reply = http_json(url, {"jsonrpc": "2.0", "id": "0", "method": method, "params": params}, login)
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    send = "--send" in sys.argv[1:]
    if len(args) != 1:
        sys.exit(__doc__)
    below = int(env_float("TOPUP_BELOW_BDX", 5) * ATOMIC)
    amount = int(env_float("TOPUP_AMOUNT_BDX", 20) * ATOMIC)
    max_per_day = int(env_float("TOPUP_MAX_PER_DAY", 2))
    state_file = os.environ.get("TOPUP_STATE_FILE", "topup-state.json")
    wallet_url = os.environ.get("TREASURY_WALLET_RPC", "").strip()
    login_file = os.environ.get("TREASURY_WALLET_LOGIN_FILE", "").strip()
    if send and not (wallet_url and login_file):
        sys.exit("!! set TREASURY_WALLET_RPC and TREASURY_WALLET_LOGIN_FILE to send")
    login = read_login(login_file) if send else None

    today = datetime.date.today().isoformat()
    try:
        state = json.load(open(state_file))
    except (OSError, ValueError):
        state = {}
    sent_today = {k: v for k, v in state.get("sent", {}).items() if v.get("day") == today}

    seats = []
    for line in open(args[0]):
        line = line.split("#", 1)[0].strip()
        if line:
            name, url = line.split()
            seats.append((name, url.rstrip("/")))

    problems = 0
    for name, url in seats:
        try:
            st = http_json(url + "/status")
        except Exception as e:  # unreachable seat: say so, pay nothing
            print(f"!! {name}: status unreachable ({e})")
            problems += 1
            continue
        balance, address = st.get("fee_wallet_balance"), st.get("fee_wallet_address")
        if balance is None or not address:
            print(f"!! {name}: reports no fee wallet (is BRIDGE_SIGNER_ACK_WALLET_RPC set?)")
            problems += 1
            continue
        if balance >= below:
            print(f"   {name}: {balance / ATOMIC:.4f} BDX, fine")
            continue
        count = sent_today.get(name, {}).get("count", 0)
        if count >= max_per_day:
            print(f"!! {name}: {balance / ATOMIC:.4f} BDX and already topped up {count}x today: look at it")
            problems += 1
            continue
        if not send:
            print(f"   {name}: {balance / ATOMIC:.4f} BDX, would send {amount / ATOMIC} BDX to {address}")
            continue
        try:
            r = wallet(wallet_url, login, "transfer",
                       {"destinations": [{"address": address, "amount": amount}], "priority": 1})
        except Exception as e:
            print(f"!! {name}: top-up failed ({e})")
            problems += 1
            continue
        sent_today[name] = {"day": today, "count": count + 1}
        print(f"   {name}: {balance / ATOMIC:.4f} BDX, sent {amount / ATOMIC} BDX to {address}: tx {r.get('tx_hash')}")
        state["sent"] = sent_today
        tmp = state_file + ".tmp"
        json.dump(state, open(tmp, "w"))
        os.replace(tmp, state_file)

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

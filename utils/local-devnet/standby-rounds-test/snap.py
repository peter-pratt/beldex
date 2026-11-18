#!/usr/bin/env python3
"""snap.py <out.jsonl>: record bridge_get_standby every 5 s whenever it changes (rounds and their
members are only reported while a round's window is open, so they must be caught live)."""
import json, sys, time, urllib.request

def rpc():
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": "bridge_get_standby", "params": {}}).encode()
    req = urllib.request.Request("http://127.0.0.1:19191/json_rpc", body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=10))["result"]

out, last = open(sys.argv[1], "a", buffering=1), None
while True:
    try:
        r = rpc()
        key = json.dumps({k: v for k, v in r.items() if k != "height"}, sort_keys=True)
        if key != last:
            out.write(json.dumps({"t": time.strftime("%H:%M:%S"), "r": r}) + "\n")
            last = key
    except Exception:
        pass
    time.sleep(5)

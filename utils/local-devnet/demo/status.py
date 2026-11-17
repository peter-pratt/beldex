#!/usr/bin/env python3
"""status.py — one screen of bridge state for the demo. Run through status.sh (refreshes).

Everything is read live from the daemons, the wallets and anvil: nothing here is cached
except the node-port <-> master-node-key map, which never changes on a running devnet.
"""
import json
import os
import subprocess
import sys
import urllib.request

LOCAL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(LOCAL, ".demo")
EVM = "http://127.0.0.1:8545"
EPOCH, UNLOCK = 120, 360
COIN = 10**9


def post(url, body, timeout=10):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def rpc(port, method, params=None):
    reply = post(f"http://127.0.0.1:{port}/json_rpc",
                 {"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}})
    if "result" not in reply:
        raise RuntimeError(f"{method}: {reply.get('error')}")
    return reply["result"]


def eth_call(to, data):
    reply = post(EVM, {"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                       "params": [{"to": to, "data": data}, "latest"]})
    return reply.get("result", "0x")


def env(path):
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def bdx(atomic):
    return f"{atomic / COIN:,.4f}"


def short(h, n=8):
    return (h[:n] + "…") if h else "-"


def main():
    if not os.path.exists(os.path.join(STATE_DIR, "demo.env")):
        print("demo-up.sh is still setting up (devnet, first DKG, contract, gateway) — "
              "this screen fills in once it prints 'Bridge demo is running'.")
        return
    br = env(os.path.join(LOCAL, "devnet-bridge.env"))
    demo = env(os.path.join(STATE_DIR, "demo.env"))
    with open(os.path.join(LOCAL, "testdata", "network_state.json")) as f:
        state = json.load(f)
    ports = [m["rpc_port"] for m in state["mns"]]

    # node port <-> master node key (cached: fixed for the life of the devnet)
    cache = os.path.join(STATE_DIR, "mn-map.json")
    try:
        with open(cache) as f:
            key_of = {int(k): v for k, v in json.load(f).items()}
    except (OSError, ValueError):
        key_of = {}
    for p in ports:
        if p not in key_of:
            try:
                key_of[p] = rpc(p, "get_master_keys")["master_node_pubkey"]
            except Exception:
                pass
    with open(cache, "w") as f:
        json.dump(key_of, f)
    port_of = {v: k for k, v in key_of.items()}
    up = {}
    for p in ports:
        try:
            rpc(p, "get_info")
            up[p] = True
        except Exception:
            up[p] = False

    info = rpc(19191, "get_info")
    h = info["height"] - 1
    epoch = h // EPOCH
    to_next = EPOCH - (h % EPOCH)
    committee = rpc(19191, "bridge_get_committee")
    seats = rpc(19191, "bridge_get_seats")
    res = rpc(19191, "bridge_get_reserves", {"gateway_id": br["GATEWAY_ID"]})
    gw = rpc(19191, "get_gateway_info", {"gateway_address": br["GATEWAY_ID"]})

    wbdx = br["WBDX"]
    signer = "0x" + eth_call(wbdx, "0x4cd615e7")[-40:]
    key_epoch = int(eth_call(wbdx, "0x6fdf657e"), 16)
    supply = int(eth_call(wbdx, "0x18160ddd"), 16)
    user_evm = "70997970C51812dc3A010C7d01b50e0d17dc79C8".lower()
    user_wbdx = int(eth_call(wbdx, "0x70a08231" + user_evm.rjust(64, "0")), 16)
    try:
        alice = rpc(int(demo["ALICE_PORT"]), "get_balance", {"account_index": 0})
        alice_bdx = f"{bdx(alice['balance'])} (unlocked {bdx(alice['unlocked_balance'])})"
    except Exception:
        alice_bdx = "?"
    observed = {o["chain_id"]: o["key_epoch"] for o in seats.get("observed_key_epoch", [])}

    print(f"\033[1mBELDEX BRIDGE DEMO\033[0m   height {h}   epoch {epoch}   "
          f"next quorum switch in {to_next} blocks (~{to_next * 4 // 60}m{to_next * 4 % 60:02d}s)")
    print()
    members = committee.get("members", [])
    print(f"\033[1mCommittee (epoch {committee.get('epoch', '?')}, {len(members)} members, "
          f"{committee.get('threshold', '?')} must sign):\033[0m  "
          + "  ".join(str(port_of.get(m, short(m))) for m in members))
    print()
    print("\033[1mKeys\033[0m")
    print(f"  wBDX signer (Pevm)   {signer}   key epoch {key_epoch}   "
          f"(Beldex has seen key epoch {observed.get(31337, '-')} via acks)")
    print(f"  gateway owner (Pgw)  {short(gw.get('owner_key', ''), 16)}   "
          f"hand-overs seen by consensus: {observed.get(0, 0)}")
    print(f"  gateway address      {br['GATEWAY_ADDR'][:20]}…  (never changes)")
    print()
    print("\033[1mMoney\033[0m")
    print(f"  wBDX supply {bdx(supply)}   ≤   BDX in gateway {bdx(res['gateway_balance'])}   "
          + ("\033[32mbacked\033[0m" if supply <= res["gateway_balance"] else "\033[31mSHORTFALL\033[0m"))
    print(f"  released this window {bdx(res['epoch_released'])} of {bdx(res['release_cap'])} cap")
    print(f"  user: Alice {alice_bdx} BDX   |   {short('0x' + user_evm, 10)} holds {bdx(user_wbdx)} wBDX")
    print()
    print("\033[1mSeats\033[0m  (port  state  bond)")
    in_committee = set(members)
    for s in sorted(seats.get("seats", []), key=lambda s: port_of.get(s["master_node_pubkey"], 0)):
        pk = s["master_node_pubkey"]
        port = port_of.get(pk, short(pk))
        if s["requested_unbond_height"]:
            unlock = s["bond_unlock_height"]
            left = max(0, unlock - h)
            st = (f"LEAVING since {s['requested_unbond_height']}, "
                  + ("still serving its key, " if s["seated"] else "key retired, ")
                  + (f"unlock in {left} blocks" if left else "unlock height reached — waiting for hand-overs"))
        else:
            st = "seated" if s["seated"] else "queued"
        mark = " ◀ committee" if pk in in_committee else ""
        node = "" if up.get(port, True) else "  \033[31m(node OFF)\033[0m"
        print(f"  {port}  {st:<60}  {bdx(s['bond'])}{mark}{node}")
    for d in seats.get("departed_bonds", []):
        print(f"  {port_of.get(d['master_node'], short(d['master_node']))}  DEREGISTERED — bond held until "
              f"its keys are retired and height {d['unlock_height']}")
    released = [p for p in ports if key_of.get(p) and key_of[p] not in {s["master_node_pubkey"] for s in seats.get("seats", [])}]
    if released:
        print(f"  no seat any more (bond released): {' '.join(map(str, released))}")
    print()
    try:
        out = subprocess.run(["pgrep", "-fc", "beldex-bridge-signer serve"], capture_output=True, text=True).stdout.strip()
    except Exception:
        out = "?"
    print(f"\033[1mSigners running:\033[0m {out}")
    print("\033[1mRotations\033[0m")
    try:
        with open(os.path.join(STATE_DIR, "rotations.log")) as f:
            for line in f.readlines()[-6:]:
                print("  " + line.rstrip())
    except OSError:
        print("  (none yet)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # keep the screen alive while something restarts
        print(f"(status unavailable: {e})")
        sys.exit(0)

#!/usr/bin/env python3
"""lan-forward.py — relay TCP connections from one address to another, for the demo.

    lan-forward.py <listen-port> <target-port> [target-host] [listen-host]

Defaults: listen on 0.0.0.0, relay to 127.0.0.1. demo-up.sh uses it to open this devnet's
node to wallets on the Wi-Fi. The friend kit uses it the other way round
(listen 127.0.0.1:8545, relay to the demo laptop's anvil), because MetaMask only accepts a
plain-http network address when it is localhost.

A plain relay (no filtering): run it only on a network you trust, only while the demo runs.
"""
import socket
import sys
import threading


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def main():
    listen_port, target_port = int(sys.argv[1]), int(sys.argv[2])
    target_host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    listen_host = sys.argv[4] if len(sys.argv) > 4 else "0.0.0.0"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(64)
    print(f"forwarding {listen_host}:{listen_port} -> {target_host}:{target_port}", flush=True)
    while True:
        client, addr = server.accept()
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=10)
            upstream.settimeout(None)
        except OSError as e:
            print(f"{addr[0]}: cannot reach {target_host}:{target_port}: {e}", flush=True)
            client.close()
            continue
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    main()

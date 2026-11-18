#!/usr/bin/env python3
"""stamp-logs.py <out> <testdata-dir>: follow every serve-*.log and append its new lines to one file,
each stamped with the time and the node (L<port> live signer, S<port> standby signer)."""
import glob, os, re, sys, time
out = open(sys.argv[1], "a", buffering=1); pos = {}
os.chdir(sys.argv[2])
skip = re.compile(r"^(watch:|outboxes:)")
while True:
    for f in glob.glob("serve-*.log"):
        try:
            # A log recreated by a restart is shorter than where we were: read it from the start.
            if os.path.getsize(f) < pos.get(f, 0): pos[f] = 0
            with open(f, errors="replace") as h:
                h.seek(pos.get(f, 0)); data = h.read(); pos[f] = h.tell()
        except OSError:
            continue
        tag = ("S" if "standby" in f else "L") + f.rsplit("-", 1)[1][:-4]
        for line in data.splitlines():
            if not skip.match(line):
                out.write(f"{time.strftime('%H:%M:%S')} {tag} {line[:300]}\n")
    time.sleep(1)

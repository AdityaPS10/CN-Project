"""Pretends to be Member 2's monitor: appends a recorded CSV to a file,
one row at a time, so live_detector.py can be tried without Mininet.

    python3 replay_feed.py                      (adaptive_ddos, 1 row/second)
    python3 replay_feed.py naive_ddos 0.1       (scenario, seconds per row)
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "sdn-ddos-monitoring", "data")
scenario = sys.argv[1] if len(sys.argv) > 1 else "adaptive_ddos"
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

src = os.path.join(DATA, "features_%s.csv" % scenario)
dst = os.path.join(HERE, "data", "replay_features.csv")
os.makedirs(os.path.dirname(dst), exist_ok=True)

with open(src) as f:
    lines = f.read().splitlines()
print("Writing %d rows of %s to %s (%.2fs per row)"
      % (len(lines) - 1, scenario, dst, delay), flush=True)
with open(dst, "w", newline="") as out:
    for line in lines:
        out.write(line + "\n")
        out.flush()
        time.sleep(delay)
print("Done.", flush=True)

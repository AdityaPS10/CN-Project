"""Live detector: follows Member 2's feature CSV while it is being written.

For every new row it runs the detector and appends the decision to an output
CSV (flushed immediately) so Member 4 can read it as it grows.
Member 2's code is not touched; the CSV is the interface.

Typical use (second terminal, while the monitor runs):
    python3 live_detector.py
Replay test without Mininet:
    python3 replay_feed.py        (terminal 1)
    python3 live_detector.py      (terminal 2)
"""
import argparse
import csv
import os
import sys
import time

from config import EXPECTED_COLUMNS
from detector import Detector
from loader import load_features, parse_row
from thresholds import calibrate

FIELDS = ["timestamp", "traffic_class", "score", "reason", "rule"]
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IN = os.path.join(HERE, "..", "sdn-ddos-monitoring", "data", "features.csv")
DEFAULT_BASE = os.path.join(HERE, "..", "sdn-ddos-monitoring", "data", "features_normal.csv")
DEFAULT_OUT = os.path.join(HERE, "data", "decisions_live.csv")


def say(msg):
    print(msg, flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--input", default=DEFAULT_IN, help="feature CSV to follow")
    ap.add_argument("--baseline", default=DEFAULT_BASE,
                    help="CSV of a NORMAL run used to calibrate")
    ap.add_argument("--output", default=DEFAULT_OUT, help="decision CSV to write")
    ap.add_argument("--poll", type=float, default=0.2, help="seconds between checks")
    ap.add_argument("--idle-exit", type=float, default=0,
                    help="stop after this many seconds without new rows (0 = never)")
    args = ap.parse_args()

    baseline = calibrate(load_features(args.baseline)[0])
    say("Baseline from %s: %s" % (os.path.basename(args.baseline), baseline))
    say("Following %s (Ctrl+C to stop)" % args.input)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    out = open(args.output, "w", newline="")
    writer = csv.DictWriter(out, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    out.flush()

    det = Detector(baseline)
    offset, inode, buf, header = 0, None, b"", None
    count, last_new = 0, time.time()

    try:
        while True:
            if not os.path.exists(args.input):
                time.sleep(args.poll)
                continue
            st = os.stat(args.input)
            if (inode is not None and st.st_ino != inode) or st.st_size < offset:
                say("-- input file was replaced/restarted: detector reset --")
                det = Detector(baseline)
                offset, buf, header = 0, b"", None
            inode = st.st_ino

            if st.st_size > offset:
                with open(args.input, "rb") as f:
                    f.seek(offset)
                    chunk = f.read()
                offset += len(chunk)
                buf += chunk
                *lines, buf = buf.split(b"\n")   # last piece may be half a line
                for raw_line in lines:
                    line = raw_line.decode("utf-8", "replace").strip("\r")
                    if not line:
                        continue
                    values = next(csv.reader([line]))
                    if header is None:
                        header = values
                        miss = [c for c in EXPECTED_COLUMNS if c not in header]
                        if miss:
                            sys.exit("Input CSV is missing columns: " + ", ".join(miss))
                        continue
                    problems = []
                    row = parse_row(dict(zip(header, values)), None, problems)
                    for _, msg in problems:
                        say("   warning: " + msg)
                    if row is None:
                        continue
                    d = det.process(row)
                    writer.writerow(d)
                    out.flush()
                    count += 1
                    say("%4d  t=%.2f  %-13s score=%-6s %s"
                        % (count, d["timestamp"], d["traffic_class"],
                           d["score"], d["reason"]))
                last_new = time.time()
            elif args.idle_exit and time.time() - last_new > args.idle_exit:
                say("No new rows for %.0fs; stopping." % args.idle_exit)
                break
            time.sleep(args.poll)
    except KeyboardInterrupt:
        say("\nStopped.")
    finally:
        out.close()
        say("%d decisions written to %s" % (count, args.output))


if __name__ == "__main__":
    main()

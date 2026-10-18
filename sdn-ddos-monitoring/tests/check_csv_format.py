"""Format check for every data/features_*.csv (the file Member 3 loads).

Run: python3 tests/check_csv_format.py
Checks: fixed header, 10 fields per row, LF line endings, HalfOpenTCPRatio empty,
timestamp spacing equal to the window size (median gap, tolerance 2 ms).
"""
import csv
import glob
import os
import statistics
import sys

EXPECTED = ["timestamp", "PacketInRate", "FlowCreationRate", "SourceIPEntropy",
            "MeanIAT", "Jitter", "FlowTableOccupancy", "ControllerRequestRate",
            "HalfOpenTCPRatio", "DataPlanePacketRate"]
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
files = sorted(glob.glob(os.path.join(root, "data", "features_*.csv")))
if not files:
    sys.exit("no data/features_*.csv files found")

failed = 0
for f in files:
    problems = []
    if b"\r" in open(f, "rb").read():
        problems.append("contains carriage returns")
    with open(f, newline="") as fh:
        rows = list(csv.reader(fh))
    if not rows or rows[0] != EXPECTED:
        problems.append("header differs from the fixed column order")
    data = rows[1:]
    differ = 0
    if any(len(r) != len(EXPECTED) for r in data):
        problems.append("a row does not have 10 fields")
    elif data:
        if any(r[8] != "" for r in data):
            problems.append("HalfOpenTCPRatio is not empty in some row")
        ts = [float(r[0]) for r in data]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        if gaps:
            med = statistics.median(gaps)
            if max(abs(g - med) for g in gaps) > 0.002:
                problems.append("timestamp spacing varies by more than 2 ms")
        differ = sum(1 for r in data if r[1] != r[7])
    status = "PASS" if not problems else "FAIL: " + "; ".join(problems)
    failed += 1 if problems else 0
    print("%-40s rows=%4d PacketInRate!=ControllerRequestRate in %d rows  %s" % (
        os.path.basename(f), len(data), differ, status))
sys.exit(1 if failed else 0)

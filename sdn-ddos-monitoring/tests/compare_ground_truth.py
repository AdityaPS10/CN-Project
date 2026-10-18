"""Step 13 check: compare monitor features with Member 1's ground-truth logs.

Usage: python3 tests/compare_ground_truth.py SCENARIO
Reads data/features_SCENARIO.csv and validation/SCENARIO/*.csv.
Ground truth is used for validation only, never as feature input.
"""
import bisect
import csv
import glob
import os
import sys
from collections import Counter

name = sys.argv[1]
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
feat_path = os.path.join(root, "data", "features_%s.csv" % name)
gt_files = sorted(glob.glob(os.path.join(root, "validation", name, "*.csv")))

gt_ts, hosts, labels = [], Counter(), Counter()
for f in gt_files:
    with open(f, newline="") as fh:
        for r in csv.DictReader(fh):
            gt_ts.append(float(r["timestamp"]))
            hosts[r["source_host"]] += 1
            labels[r["scenario"] + "/" + r["attack_level"]] += 1
gt_ts.sort()
print("ground-truth files:", [os.path.basename(f) for f in gt_files])
if not gt_ts:
    sys.exit("no ground-truth packets found")
print("ground-truth packets:", len(gt_ts), "per host:", dict(hosts), "labels:", dict(labels))

with open(feat_path, newline="") as fh:
    rows = list(csv.DictReader(fh))
print("feature rows:", len(rows))


def count(lo, hi):
    return bisect.bisect_right(gt_ts, hi) - bisect.bisect_right(gt_ts, lo)


t0 = gt_ts[0]
table = []
for r in rows:
    T = float(r["timestamp"])
    table.append((T, r, count(T - 1, T), count(T - 2, T - 1)))

print("")
print("t_rel  PktIn NewFl Entropy Occ  DataPlane  GT_same GT_prev")
for T, r, g0, g1 in table:
    if g0 or g1 or float(r["FlowCreationRate"]) > 0:
        print("%5.0f  %5s %5s %7s %3s  %9s  %7d %7d" % (
            T - t0, r["PacketInRate"], r["FlowCreationRate"],
            r["SourceIPEntropy"], r["FlowTableOccupancy"],
            r["DataPlanePacketRate"], g0, g1))

span = [x for x in table if t0 - 2 <= x[0] <= gt_ts[-1] + 3]
if span:
    mae0 = sum(abs(float(x[1]["DataPlanePacketRate"]) - x[2]) for x in span) / len(span)
    mae1 = sum(abs(float(x[1]["DataPlanePacketRate"]) - x[3]) for x in span) / len(span)
    print("")
    print("rows compared:", len(span))
    print("mean abs difference vs same window: %.1f   vs previous window: %.1f" % (mae0, mae1))
    print("sum DataPlanePacketRate: %.0f   ground-truth packets: %d" % (
        sum(float(x[1]["DataPlanePacketRate"]) for x in span), len(gt_ts)))

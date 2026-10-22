"""Run the combined detector on all four scenarios; write decision CSVs."""
import csv

from detector import Detector
from loader import load_features
from thresholds import calibrate

DATA = "../sdn-ddos-monitoring/data/features_%s.csv"
OUT = "data/decisions_%s.csv"
SCENARIOS = ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos"]
SYMBOL = {"normal": ".", "flash_crowd": "F", "naive_ddos": "N",
          "adaptive_ddos": "A", "unknown": "?"}

baseline = calibrate(load_features(DATA % "normal")[0])
print("Legend: . normal  F flash_crowd  N naive_ddos  A adaptive_ddos  ? unknown")

for name in SCENARIOS:
    rows, _ = load_features(DATA % name)
    det = Detector(baseline)
    decisions = [det.process(r) for r in rows]
    counts = {}
    for d in decisions:
        counts[d["traffic_class"]] = counts.get(d["traffic_class"], 0) + 1
    print("\n%s  %s" % (name, counts))
    print("".join(SYMBOL[d["traffic_class"]] for d in decisions))
    with open(OUT % name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp", "traffic_class",
                                          "score", "reason", "rule"])
        w.writeheader()
        w.writerows(decisions)
print("\nDecision files written to data/decisions_<scenario>.csv")

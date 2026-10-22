"""Threshold-only vs CUSUM-only on the same data."""
from config import (CUSUM_FEATURE, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR,
                    THRESHOLD_FEATURES)
from cusum import Cusum
from loader import load_features
from thresholds import calibrate

DATA = "../sdn-ddos-monitoring/data/features_%s.csv"
SCENARIOS = ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos"]

normal_rows, _ = load_features(DATA % "normal")
baseline = calibrate(normal_rows)
mu = baseline[CUSUM_FEATURE]
limit = THRESHOLD_FEATURES[CUSUM_FEATURE] * mu
print("Baseline mu=%.1f  threshold limit=%.1f  CUSUM k=%.1f h=%.1f"
      % (mu, limit, CUSUM_K, CUSUM_H))


def first(flags):
    return flags.index(True) if True in flags else None


def show(name, values):
    thr = [v is not None and v > limit for v in values]
    c = Cusum(mu, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR)
    cus = [c.update(v)[1] for v in values]
    print("\n%-22s windows=%3d" % (name, len(values)))
    print("  threshold: flagged=%3d first=%s" % (sum(thr), first(thr)))
    print("  CUSUM    : flagged=%3d first=%s" % (sum(cus), first(cus)))


for name in SCENARIOS:
    rows, _ = load_features(DATA % name)
    show(name, [r[CUSUM_FEATURE] for r in rows])

# SYNTHETIC example (not experiment data): slow ramp 20 -> 80 packets/s
ramp = [20.0] * 10 + [20.0 + i for i in range(1, 61)] + [80.0] * 10
show("SYNTHETIC slow ramp", ramp)

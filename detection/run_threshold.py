"""Threshold-only detector: calibrate on the normal run, test on all four."""
from loader import load_features
from thresholds import calibrate, check_row

DATA = "../sdn-ddos-monitoring/data/features_%s.csv"
SCENARIOS = ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos"]

normal_rows, _ = load_features(DATA % "normal")
baseline = calibrate(normal_rows)
print("Baseline (median of active normal windows):", baseline)
print("Legend: '#' = flagged, '.' = not flagged\n")

for name in SCENARIOS:
    rows, _ = load_features(DATA % name)
    flags = [bool(check_row(r, baseline)) for r in rows]
    first = flags.index(True) if True in flags else None
    print("%-14s windows=%3d flagged=%3d first_flag_at_window=%s"
          % (name, len(rows), sum(flags), first))
    print("".join("#" if f else "." for f in flags))
    print()

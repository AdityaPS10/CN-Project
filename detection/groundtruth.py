"""Build per-window true labels from Member 1's packet logs."""
import csv
import glob
import math

from config import GROUND_TRUTH_LAG

LOGS = "../sdn-ddos-monitoring/validation/%s/*.csv"


def packet_times(scenario):
    times = []
    for path in glob.glob(LOGS % scenario):
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                times.append(float(r["timestamp"]))
    return times


def truth_labels(scenario, rows):
    """One true label per feature row.

    A window is labelled with the scenario name if it falls between the first
    and last logged packet of that scenario (so pauses INSIDE an adaptive
    attack still count as attack). Everything else is 'normal'.
    """
    labels = ["normal"] * len(rows)
    times = packet_times(scenario)
    if scenario == "normal" or not times:
        return labels
    t0 = rows[0]["timestamp"]
    first = math.floor(min(times) - t0)
    last = math.floor(max(times) - t0)
    for j in range(len(rows)):
        if first <= j - GROUND_TRUTH_LAG <= last:
            labels[j] = scenario
    return labels

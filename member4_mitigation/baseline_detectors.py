"""Member 4 - live threshold-only, CUSUM-only and entropy-only detectors (baselines).

These reuse Member 3's own building blocks (thresholds.calibrate, Cusum,
the same DataPlanePacketRate feature, baseline and limits) and Member 3's
live_detector.py file-following loop; only the classification step is
swapped. That way the baselines differ from the proposed detector ONLY in
the decision logic, and feed the SAME mitigation policy.

A single-signal detector cannot tell a flash crowd from an attack, so every
alarm is reported as an attack. It is written as traffic_class=naive_ddos
with rule=threshold|cusum|entropy and a reason that says it is a baseline alarm.

Run from the project root, exactly like live_detector.py:
    python3 -m member4_mitigation.baseline_detectors --mode threshold [--output ...]
    python3 -m member4_mitigation.baseline_detectors --mode cusum     [--output ...]
    python3 -m member4_mitigation.baseline_detectors --mode entropy   [--output ...]

Entropy-only uses Member 2's SourceIPEntropy (Shannon entropy, bits, of the
source IPs seen in Packet-Ins per window). Its baseline is the mean and
population standard deviation of that feature over ALL windows of the same
normal-traffic file Member 3 calibrates on; a window alarms if
    H > max(mean + ENTROPY_K * std, ENTROPY_MIN_BITS)
(defaults 3 and 1.0 bit = "more than two equally active new sources").
Because Member 1's controller installs permanent flows, Packet-Ins (and so
this feature) are almost always 0 after flow setup; the entropy baseline is
implemented and measured anyway, so the report can show that, not assume it.
"""
import os
import sys

DETECTION_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "detection")
if DETECTION_DIR not in sys.path:
    sys.path.insert(0, DETECTION_DIR)

from config import (CUSUM_FEATURE, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR,  # noqa: E402
                    THRESHOLD_FEATURES)
from cusum import Cusum  # noqa: E402

ENTROPY_FEATURE = "SourceIPEntropy"
ENTROPY_K = 3.0
ENTROPY_MIN_BITS = 1.0
DEFAULT_BASELINE_CSV = os.path.join(DETECTION_DIR, "..", "sdn-ddos-monitoring", "data",
                                    "features_normal.csv")

FEATURE = CUSUM_FEATURE


def _out(row, cls, score, reason, rule):
    return {"timestamp": row.get("timestamp"), "traffic_class": cls,
            "score": round(score, 3), "reason": reason, "rule": rule}


class ThresholdOnlyDetector:
    def __init__(self, baseline):
        self.limit = THRESHOLD_FEATURES[FEATURE] * baseline[FEATURE]

    def process(self, row):
        x = row.get(FEATURE)
        if x is None:
            return _out(row, "unknown", 0.0, FEATURE + " missing", "missing_input")
        score = x / self.limit
        if x > self.limit:
            return _out(row, "naive_ddos", score, "baseline threshold alarm: rate %.0f > %.0f"
                        % (x, self.limit), "threshold")
        return _out(row, "normal", score, "within normal range", "none")


class CusumOnlyDetector:
    def __init__(self, baseline):
        self.cusum = Cusum(baseline[FEATURE], CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR)

    def process(self, row):
        x = row.get(FEATURE)
        if x is None:
            return _out(row, "unknown", 0.0, FEATURE + " missing", "missing_input")
        s, alarm = self.cusum.update(x)
        score = s / CUSUM_H
        if alarm:
            return _out(row, "naive_ddos", score, "baseline CUSUM alarm: S=%.0f > h=%.0f"
                        % (s, CUSUM_H), "cusum")
        return _out(row, "normal", score, "within normal range", "none")


class EntropyOnlyDetector:
    baseline_csv = DEFAULT_BASELINE_CSV      # main() points this at --baseline if given

    def __init__(self, baseline, entropy_stats=None):
        if entropy_stats is None:
            entropy_stats = entropy_baseline(self.baseline_csv)
        mean, std = entropy_stats
        self.limit = max(mean + ENTROPY_K * std, ENTROPY_MIN_BITS)

    def process(self, row):
        h = row.get(ENTROPY_FEATURE)
        if h is None:
            return _out(row, "unknown", 0.0, ENTROPY_FEATURE + " missing", "missing_input")
        score = h / self.limit
        if h > self.limit:
            return _out(row, "naive_ddos", score, "baseline entropy alarm: H=%.2f > %.2f bits"
                        % (h, self.limit), "entropy")
        return _out(row, "normal", score, "within normal range", "none")


def entropy_baseline(path):
    """(mean, population std) of SourceIPEntropy over all windows of a normal run."""
    from loader import load_features
    rows, _ = load_features(path)
    xs = [r[ENTROPY_FEATURE] for r in rows if r[ENTROPY_FEATURE] is not None]
    if not xs:
        raise ValueError("no %s values in %s" % (ENTROPY_FEATURE, path))
    mean = sum(xs) / len(xs)
    std = (sum((x - mean) ** 2 for x in xs) / len(xs)) ** 0.5
    return mean, std


MODES = {"threshold": ThresholdOnlyDetector, "cusum": CusumOnlyDetector,
         "entropy": EntropyOnlyDetector}


def main():
    argv = sys.argv[1:]
    if "--mode" not in argv or argv.index("--mode") + 1 >= len(argv):
        sys.exit("usage: python3 -m member4_mitigation.baseline_detectors --mode {%s} "
                 "[live_detector.py options]" % "|".join(MODES))
    i = argv.index("--mode")
    mode = argv[i + 1]
    if mode not in MODES:
        sys.exit("unknown mode %r (choose %s)" % (mode, ", ".join(MODES)))
    rest = argv[:i] + argv[i + 2:]
    if "--baseline" in rest and rest.index("--baseline") + 1 < len(rest):
        EntropyOnlyDetector.baseline_csv = rest[rest.index("--baseline") + 1]

    import live_detector
    live_detector.Detector = MODES[mode]       # swap only the classifier
    print("[baseline_detectors] mode=%s (Member 3's live loop, %s classifier)"
          % (mode, MODES[mode].__name__), flush=True)
    sys.argv = ["live_detector.py"] + rest
    live_detector.main()


if __name__ == "__main__":
    main()

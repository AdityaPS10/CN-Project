"""Compare threshold-only, CUSUM-only and the combined detector.

All numbers come from the labelled runs; nothing is estimated.
Task A: abnormal (flash crowd or attack) vs normal.
Task B: attack (naive or adaptive) vs legitimate (normal or flash crowd).
"""
from config import CUSUM_FEATURE, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR, \
    THRESHOLD_FEATURES
from cusum import Cusum
from detector import Detector
from groundtruth import truth_labels
from loader import load_features
from thresholds import calibrate

DATA = "../sdn-ddos-monitoring/data/features_%s.csv"
SCENARIOS = ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos"]
CLASSES = ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos", "unknown"]
ATTACKS = ("naive_ddos", "adaptive_ddos")
METHODS = ["threshold", "cusum", "combined"]

baseline = calibrate(load_features(DATA % "normal")[0])
mu = baseline[CUSUM_FEATURE]
limit = THRESHOLD_FEATURES[CUSUM_FEATURE] * mu

runs = {}
for name in SCENARIOS:
    rows, _ = load_features(DATA % name)
    truth = truth_labels(name, rows)
    det = Detector(baseline)
    comb = [det.process(r)["traffic_class"] for r in rows]
    c = Cusum(mu, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR)
    xs = [r[CUSUM_FEATURE] for r in rows]
    runs[name] = {
        "truth": truth, "comb": comb,
        "threshold_flag": [x is not None and x > limit for x in xs],
        "cusum_flag": [c.update(x)[1] for x in xs],
    }


def counts(truth_pos, pred_pos):
    tp = sum(t and p for t, p in zip(truth_pos, pred_pos))
    fp = sum((not t) and p for t, p in zip(truth_pos, pred_pos))
    fn = sum(t and (not p) for t, p in zip(truth_pos, pred_pos))
    tn = sum((not t) and (not p) for t, p in zip(truth_pos, pred_pos))
    return tp, fp, fn, tn


def ratio(a, b):
    return "  n/a" if b == 0 else "%.3f" % (a / b)


def predictions(run, method, task):
    if method == "threshold":
        return run["threshold_flag"]
    if method == "cusum":
        return run["cusum_flag"]
    if task == "A":
        return [c in ("flash_crowd",) + ATTACKS for c in run["comb"]]
    return [c in ATTACKS for c in run["comb"]]


def truth_pos(run, task):
    if task == "A":
        return [t != "normal" for t in run["truth"]]
    return [t in ATTACKS for t in run["truth"]]


for task, title in (("A", "Task A: abnormal vs normal"),
                    ("B", "Task B: attack vs legitimate (flash crowd = legitimate)")):
    print("\n=== %s (all 4 scenarios pooled) ===" % title)
    print("%-10s %4s %4s %4s %5s | %9s %6s %6s %6s"
          % ("method", "TP", "FP", "FN", "TN", "precision", "recall", "F1", "FPR"))
    for m in METHODS:
        t_all, p_all = [], []
        for name in SCENARIOS:
            t_all += truth_pos(runs[name], task)
            p_all += predictions(runs[name], m, task)
        tp, fp, fn, tn = counts(t_all, p_all)
        prec = tp / (tp + fp) if tp + fp else None
        rec = tp / (tp + fn) if tp + fn else None
        f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
        f = lambda v: "  n/a" if v is None else "%.3f" % v
        print("%-10s %4d %4d %4d %5d | %9s %6s %6s %6s"
              % (m, tp, fp, fn, tn, f(prec), f(rec), f(f1), ratio(fp, fp + tn)))

print("\n=== Detection latency, Task B (windows from first true attack window"
      " to first alarm) ===")
for name in ATTACKS:
    t = truth_pos(runs[name], "B")
    onset = t.index(True)
    cells = []
    for m in METHODS:
        p = predictions(runs[name], m, "B")
        first = p.index(True) if True in p else None
        cells.append("%s=%s" % (m, "none" if first is None else first - onset))
    print("%-14s onset_row=%d  %s" % (name, onset, "  ".join(cells)))

print("\n=== Combined detector: confusion matrix (rows = truth, cols = predicted) ===")
print("%-14s" % "" + "".join("%14s" % c for c in CLASSES))
for tcls in SCENARIOS:
    row = {c: 0 for c in CLASSES}
    for name in SCENARIOS:
        for tr, pr in zip(runs[name]["truth"], runs[name]["comb"]):
            if tr == tcls:
                row[pr] += 1
    print("%-14s" % tcls + "".join("%14d" % row[c] for c in CLASSES))

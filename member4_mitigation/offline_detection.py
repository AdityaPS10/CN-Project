"""Member 4 - detection baselines on IDENTICAL traffic (replay of recorded features).

    python3 -m member4_mitigation.offline_detection [results_dir]

For every recorded run, the features Member 2 measured live (features.csv)
are fed, in order, through four detectors that all use Member 3's baseline
(calibrated on sdn-ddos-monitoring/data/features_normal.csv):

    combined   Member 3's proposed detector (detection/detector.py)
    threshold  rate > 3 x baseline                  (baseline_detectors.py)
    cusum      capped one-sided CUSUM               (baseline_detectors.py)
    entropy    SourceIPEntropy above its baseline   (baseline_detectors.py)

Every detector sees exactly the same windows, so differences are due to the
decision logic only. Scored with the same ground truth and evaluation window
as evaluator.py. This is a REPLAY of recorded measurements (no new traffic);
mitigation effects still come from the live runs (compare.py).

Determinism check: for runs whose live detector was 'combined', the replayed
decisions must equal the live decisions.csv row for row; the result of that
check is printed and written to the report.

Writes results/offline_detection.md and results/offline_detection.csv.
"""
import csv
import glob
import json
import os
import sys
from collections import defaultdict

from member4_mitigation import baseline_detectors as bd
from member4_mitigation.decisions import parse_row, read_decisions
from member4_mitigation.evaluator import detection_metrics, load_sent

from detector import Detector            # Member 3 (detection/ is on sys.path via bd)
from loader import load_features
from thresholds import calibrate

HERE = os.path.dirname(os.path.abspath(__file__))
DETECTORS = ["combined", "threshold", "cusum", "entropy"]


def make_detectors(baseline, entropy_stats):
    return {"combined": Detector(baseline),
            "threshold": bd.ThresholdOnlyDetector(baseline),
            "cusum": bd.CusumOnlyDetector(baseline),
            "entropy": bd.EntropyOnlyDetector(baseline, entropy_stats)}


def replay_run(run_dir, baseline, entropy_stats):
    """Returns ({detector: metrics}, determinism_ok or None)."""
    with open(os.path.join(run_dir, "meta.json")) as f:
        meta = json.load(f)
    rows, _ = load_features(os.path.join(run_dir, "features.csv"))
    dets = make_detectors(baseline, entropy_stats)
    decisions = {name: [] for name in dets}
    for row in rows:
        for name, det in dets.items():
            out = det.process(row)
            decisions[name].append(parse_row({k: str(v) for k, v in out.items()}))

    sent = load_sent(run_dir)
    atk = [t for h in meta["attack_hosts"] for t in sent.get(h, [])]
    attack_iv = (min(atk), max(atk)) if atk else None
    t_from, t_to = meta["t_bg_start"], meta.get("t_stop", meta["t_run_end"])
    metrics = {name: detection_metrics(ds, attack_iv, t_from, t_to, [])
               for name, ds in decisions.items()}

    same = None
    live_path = os.path.join(run_dir, "decisions.csv")
    if meta["detector"] == "combined" and os.path.exists(live_path):
        live = read_decisions(live_path)
        rep = decisions["combined"]
        n = min(len(live), len(rep))
        same = n > 0 and all(abs(a.timestamp - b.timestamp) < 1e-6 and
                             a.traffic_class == b.traffic_class and a.rule == b.rule
                             for a, b in zip(live[:n], rep[:n]))
    return meta, metrics, same


def _ratio(a, b):
    return a / b if b else None


def _f(v, nd=3):
    return "n/a" if v is None else ("%." + str(nd) + "f") % v


def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results")
    baseline = calibrate(load_features(bd.DEFAULT_BASELINE_CSV)[0])
    entropy_stats = bd.entropy_baseline(bd.DEFAULT_BASELINE_CSV)

    def complete(d):
        try:
            with open(os.path.join(d, "meta.json")) as f:
                meta = json.load(f)
        except (OSError, ValueError):
            return False
        # Aborted (stopped) runs have no full scenario and are left out.
        return meta.get("status", "finished") == "finished" and \
            os.path.exists(os.path.join(d, "features.csv"))
    runs = sorted(d for d in glob.glob(os.path.join(results_dir, "*")) if complete(d))
    if not runs:
        sys.exit("no recorded runs with features.csv under %s" % results_dir)

    per_run, pooled, by_scen = [], defaultdict(lambda: defaultdict(int)), defaultdict(list)
    det_checked = det_ok = 0
    for run in runs:
        meta, metrics, same = replay_run(run, baseline, entropy_stats)
        if same is not None:
            det_checked += 1
            det_ok += bool(same)
        scen = meta["scenario"] + ("/" + meta["attack_level"] if meta.get("attack_level") else "")
        for name, m in metrics.items():
            per_run.append([os.path.basename(run), scen, name, m["tp"], m["fp"], m["fn"], m["tn"],
                            m["detection_latency_s"]])
            for k in ("tp", "fp", "fn", "tn"):
                pooled[name][k] += m[k]
            by_scen[(scen, name)].append(m)

    with open(os.path.join(results_dir, "offline_detection.csv"), "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["run_id", "scenario", "detector", "tp", "fp", "fn", "tn", "detection_latency_s"])
        w.writerows(per_run)

    md = ["# Detection baselines on identical traffic (replay of recorded features)", "",
          "Generated by `python3 -m member4_mitigation.offline_detection` from %d recorded runs." % len(runs),
          "Each detector processed exactly the same feature windows (Member 2's live `features.csv`",
          "of every run). Ground truth and evaluation window as in `evaluator.py`; positive =",
          "attack (naive or adaptive). This is a replay of real measurements, not new traffic.", "",
          "Determinism check: replayed combined decisions equal the live `decisions.csv` in "
          "%d of %d runs recorded with the combined detector." % (det_ok, det_checked), "",
          "## Pooled over all runs (windows)", "",
          "| Detector | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for name in DETECTORS:
        p = pooled[name]
        prec, rec = _ratio(p["tp"], p["tp"] + p["fp"]), _ratio(p["tp"], p["tp"] + p["fn"])
        f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if p["tp"] == 0 else None)
        md.append("| %s | %d | %d | %d | %d | %s | %s | %s | %s | %s |" % (
            name, p["tp"], p["fp"], p["fn"], p["tn"], _f(prec), _f(rec), _f(f1),
            _f(_ratio(p["fp"], p["fp"] + p["tn"])), _f(_ratio(p["fn"], p["fn"] + p["tp"]))))
    md += ["", "## Per scenario: false-positive windows (legitimate scenarios) and recall / mean latency (attacks)", "",
           "| Scenario | Runs | " + " | ".join(DETECTORS) + " |", "|---|---|" + "---|" * len(DETECTORS)]
    for scen in sorted({k[0] for k in by_scen}):
        cells = []
        for name in DETECTORS:
            ms = by_scen[(scen, name)]
            tp, fp, fn = (sum(m[k] for m in ms) for k in ("tp", "fp", "fn"))
            if tp + fn == 0:
                cells.append("FP %d" % fp)
            else:
                lats = [m["detection_latency_s"] for m in ms if m["detection_latency_s"] is not None]
                cells.append("recall %s, latency %s s" % (_f(_ratio(tp, tp + fn), 2),
                                                          _f(sum(lats) / len(lats), 1) if lats else "none"))
        md.append("| %s | %d | %s |" % (scen, len(by_scen[(scen, DETECTORS[0])]), " | ".join(cells)))
    text = "\n".join(md) + "\n"
    with open(os.path.join(results_dir, "offline_detection.md"), "w") as f:
        f.write(text)
    print(text)
    if det_checked and det_ok != det_checked:
        print("WARNING: replay differs from live decisions in %d run(s)" % (det_checked - det_ok))


if __name__ == "__main__":
    main()

"""Member 4 - compares runs: baseline vs proposed, detection vs mitigation.

    python3 -m member4_mitigation.compare [results_dir]

Reads every results/<run>/metrics.json and writes:
    results/summary.csv   one row per run, all main metrics (machine-readable)
    results/summary.md    two tables for the report:
      A. detection, pooled per detector over all its runs (window counts summed)
      B. mitigation/network, one row per run configuration (mean over repeats)

Detection (table A) and mitigation (table B) are kept apart on purpose, so
the report can tell whether an improvement comes from better detection,
from mitigation, or from both. Only recorded runs are used; the number of
runs behind every row is printed.
"""
import csv
import glob
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

COLUMNS = [
    ("run_id", lambda m: m["run_id"]),
    ("scenario", lambda m: m["scenario"]),
    ("attack_level", lambda m: m["attack_level"] or ""),
    ("detector", lambda m: m["detector"]),
    ("mitigation", lambda m: m["mitigation"]),
    ("overrides", lambda m: " ".join("%s=%s" % kv for kv in sorted(m["config_overrides"].items()))),
    ("tp", lambda m: m["detection"]["tp"]),
    ("fp", lambda m: m["detection"]["fp"]),
    ("fn", lambda m: m["detection"]["fn"]),
    ("tn", lambda m: m["detection"]["tn"]),
    ("detection_latency_s", lambda m: m["detection"]["detection_latency_s"]),
    ("response_time_s", lambda m: m["mitigation_actions"]["response_time_s"]),
    ("decision_to_rule_applied_ms", lambda m: m["mitigation_actions"]["decision_to_rule_applied_ms"]),
    ("release_delay_s", lambda m: m["mitigation_actions"]["release_delay_s"]),
    ("released_before_attack_end", lambda m: m["mitigation_actions"].get("released_before_attack_end")),
    ("rate_limits_installed", lambda m: m["mitigation_actions"]["rate_limits_installed"]),
    ("legit_hosts_limited", lambda m: len(m["mitigation_actions"]["legit_hosts_limited"])),
    ("attack_hosts_limited", lambda m: len(m["mitigation_actions"]["attack_hosts_limited"])),
    ("legit_pdr_focus", lambda m: m["traffic"]["legit_during_focus"]["pdr"]),
    ("legit_rx_pps_focus", lambda m: m["traffic"]["legit_during_focus"]["received_pps"]),
    ("attack_pdr_focus", lambda m: (m["traffic"]["attack_during_focus"] or {}).get("pdr")),
    ("attack_rx_pps_focus", lambda m: (m["traffic"]["attack_during_focus"] or {}).get("received_pps")),
    ("victim_rx_kbps_focus", lambda m: m["traffic"]["victim_total_during_focus"]["received_kbps"]),
    ("ping_rtt_focus_ms", lambda m: m["ping_h6"]["rtt_avg_during_focus_ms"]),
    ("ping_loss_pct", lambda m: m["ping_h6"]["loss_pct"]),
    ("flow_table_max", lambda m: m["switch"]["flow_table_max_entries"]),
    ("packet_in_total", lambda m: m["switch"]["packet_in_total"]),
    ("ovs_max_m4_flows", lambda m: (m.get("switch_view") or {}).get("max_m4_flows_on_switch")),
    ("ovs_meter_dropped", lambda m: (m.get("switch_view") or {}).get("meter_packets_dropped_max")),
    ("controller_cpu_mean_pct", lambda m: m["resources"].get("controller", {}).get("cpu_mean_pct")),
    ("controller_cpu_max_pct", lambda m: m["resources"].get("controller", {}).get("cpu_max_pct")),
    ("controller_rss_max_mib", lambda m: m["resources"].get("controller", {}).get("rss_max_mib")),
    ("detector_cpu_mean_pct", lambda m: m["resources"].get("detector", {}).get("cpu_mean_pct")),
    ("duration_s", lambda m: m["duration_s"]),
]


def load(results_dir):
    runs = []
    for path in sorted(glob.glob(os.path.join(results_dir, "*", "metrics.json"))):
        with open(path) as f:
            runs.append(json.load(f))
    return runs


def _f(v, nd=3):
    if v is None or v == "":
        return "n/a"
    return ("%." + str(nd) + "f") % v if isinstance(v, float) else str(v)


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def detection_table(runs):
    pooled = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "n": 0, "lat": defaultdict(list)})
    for m in runs:
        p = pooled[m["detector"]]
        for k in ("tp", "fp", "fn", "tn"):
            p[k] += m["detection"][k]
        p["n"] += 1
        if m["detection"]["detection_latency_s"] is not None:
            key = m["scenario"] + ("/" + m["attack_level"] if m["attack_level"] else "")
            p["lat"][key].append(m["detection"]["detection_latency_s"])
    out = ["| Detector | Runs | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR | Mean latency (s) |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for det in sorted(pooled):
        p = pooled[det]
        prec = p["tp"] / (p["tp"] + p["fp"]) if p["tp"] + p["fp"] else None
        rec = p["tp"] / (p["tp"] + p["fn"]) if p["tp"] + p["fn"] else None
        f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
        fpr = p["fp"] / (p["fp"] + p["tn"]) if p["fp"] + p["tn"] else None
        fnr = p["fn"] / (p["fn"] + p["tp"]) if p["fn"] + p["tp"] else None
        lat = ", ".join("%s %s" % (k, _f(_mean(v), 1)) for k, v in sorted(p["lat"].items())) or "n/a"
        out.append("| %s | %d | %d | %d | %d | %d | %s | %s | %s | %s | %s | %s |" % (
            det, p["n"], p["tp"], p["fp"], p["fn"], p["tn"],
            _f(prec), _f(rec), _f(f1), _f(fpr), _f(fnr), lat))
    return out


def mitigation_table(runs):
    groups = defaultdict(list)
    for m in runs:
        key = (m["scenario"], m["attack_level"] or "", m["detector"], m["mitigation"],
               " ".join("%s=%s" % kv for kv in sorted(m["config_overrides"].items())))
        groups[key].append(m)
    cols = ["legit_pdr_focus", "legit_rx_pps_focus", "attack_pdr_focus", "attack_rx_pps_focus",
            "response_time_s", "release_delay_s", "legit_hosts_limited", "ping_rtt_focus_ms",
            "flow_table_max", "packet_in_total", "controller_cpu_mean_pct", "controller_rss_max_mib"]
    get = dict(COLUMNS)
    out = ["| Scenario | Level | Detector | Mitigation | Overrides | Runs | " +
           " | ".join(cols) + " |", "|" + "---|" * (6 + len(cols))]
    for key in sorted(groups):
        ms = groups[key]
        vals = [_f(_mean(get[c](m) for m in ms), 3 if ("pdr" in c or c.endswith("_ms")) else 1) for c in cols]
        out.append("| %s | %s | %s | %s | %s | %d | " % (key[0], key[1] or "-", key[2], key[3],
                                                        key[4] or "-", len(ms)) +
                   " | ".join(vals) + " |")
    return out


def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results")
    runs = load(results_dir)
    if not runs:
        sys.exit("no metrics.json found under %s" % results_dir)

    with open(os.path.join(results_dir, "summary.csv"), "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow([c for c, _ in COLUMNS])
        for m in runs:
            w.writerow([_f(fn(m), 4) if isinstance(fn(m), float) else fn(m) for _, fn in COLUMNS])

    md = ["# Member 4 results summary", "",
          "Generated by `python3 -m member4_mitigation.compare` from %d recorded run(s)." % len(runs),
          "Units: PDR = delivered/sent (0-1); pps = packets/s at the victim; times in s;",
          "CPU in %% of one core; memory in MiB. 'focus' = attack interval (attack runs)",
          "or scenario interval (normal / flash-crowd runs).", "",
          "## A. Detection (per detector, windows pooled over all its runs)", ""]
    md += detection_table(runs)
    md += ["", "## B. Mitigation and network impact (mean over runs of each configuration)", ""]
    md += mitigation_table(runs)
    text = "\n".join(md) + "\n"
    with open(os.path.join(results_dir, "summary.md"), "w") as f:
        f.write(text)
    print(text)
    print("written: %s/summary.csv and summary.md" % results_dir)


if __name__ == "__main__":
    main()

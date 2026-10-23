"""Member 4 - computes all metrics of ONE run folder from recorded data only.

    python3 -m member4_mitigation.evaluator member4_mitigation/results/<run>

Inputs (written by run_experiment.py): meta.json, decisions.csv (detector),
actions.csv / events.csv (our app), traffic/*.csv (Member 1 generators,
one row per packet SENT), sink.csv (packets RECEIVED at h1 per second and
source), ping_h6.txt, features.csv (Member 2), resources.csv.

Every metric name carries its unit (_s seconds, _ms milliseconds, _pps
packets/second, _kbps kilobits/second of UDP payload, _mib mebibytes,
_pct percent). Ratios are 0..1. A value is None when it is undefined for
the run (e.g. response time in a run without an attack) - never guessed.

Ground truth for detection (same convention as Member 3's evaluate.py):
the attack interval is first..last packet sent by the attack hosts, pauses
included. A decision row with timestamp T describes traffic of the window
(T-1-LAG, T-LAG], LAG = 2 s (Member 3's measured feature lag); the row is
"attack" if that window overlaps the attack interval.
"""
import csv
import glob
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

from member4_mitigation.decisions import read_decisions, ATTACK_CLASSES

LAG_S = 2.0
METRICS_FILE = "metrics.json"


# ------------------------------------------------------------------ helpers
def _ratio(a, b):
    return None if not b else a / b


def _mean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else None


def _rows(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _float(v):
    try:
        x = float(v)
        return None if math.isnan(x) else x
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ loading
def load_sent(run_dir):
    """host -> sorted list of send timestamps (one per packet)."""
    sent = defaultdict(list)
    for path in glob.glob(os.path.join(run_dir, "traffic", "*.csv")):
        for r in _rows(path):
            t = _float(r.get("timestamp"))
            if t is not None:
                sent[r["source_host"]].append(t)
    for v in sent.values():
        v.sort()
    return sent


def load_received(run_dir, ip_to_host):
    """host -> {second: (packets, bytes)} measured at the sink."""
    recv = defaultdict(dict)
    for r in _rows(os.path.join(run_dir, "sink.csv")):
        host = ip_to_host.get(r["src_ip"], r["src_ip"])
        recv[host][int(r["second"])] = (int(r["packets"]), int(r["bytes"]))
    return recv


PING_LINE = re.compile(r"^\[(\d+\.\d+)\].*time=([\d.]+) ms")
PING_SUMMARY = re.compile(r"(\d+) packets transmitted, (\d+) received")


def load_ping(run_dir, host):
    path = os.path.join(run_dir, "ping_%s.txt" % host)
    samples, tx, rx = [], None, None
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                m = PING_LINE.match(line)
                if m:
                    samples.append((float(m.group(1)), float(m.group(2))))
                m = PING_SUMMARY.search(line)
                if m:
                    tx, rx = int(m.group(1)), int(m.group(2))
    return samples, tx, rx


# ------------------------------------------------------------------ metrics
def detection_metrics(decisions, attack_iv, t_from, t_to, actions):
    rows = [d for d in decisions if t_from <= d.timestamp - LAG_S <= t_to]
    tp = fp = fn = tn = 0
    for d in rows:
        end = d.timestamp - LAG_S
        truth = attack_iv is not None and attack_iv[0] <= end and attack_iv[1] > end - 1.0
        pred = d.traffic_class in ATTACK_CLASSES
        tp += truth and pred
        fp += (not truth) and pred
        fn += truth and not pred
        tn += (not truth) and not pred
    prec, rec = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    out = {"windows": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
           "precision": prec, "recall": rec,
           "f1": (2 * prec * rec / (prec + rec)) if prec and rec else (0.0 if tp == 0 and (fp or fn) else None),
           "fpr": _ratio(fp, fp + tn), "fnr": _ratio(fn, fn + tp),
           "class_counts": dict(Counter(d.traffic_class for d in rows)),
           "detection_latency_s": None, "decision_received_latency_s": None}
    if attack_iv is not None:
        first = next((d for d in rows if d.timestamp >= attack_iv[0]
                      and d.traffic_class in ATTACK_CLASSES), None)
        if first is not None:
            out["detection_latency_s"] = first.timestamp - attack_iv[0]
            got = next((_float(a["wall_time"]) for a in actions
                        if abs(_float(a["decision_timestamp"]) - first.timestamp) < 1e-3), None)
            if got is not None:
                out["decision_received_latency_s"] = got - attack_iv[0]
    return out


def traffic_metrics(sent, recv, hosts, s_from, s_to, payload_bytes=128):
    """Delivery and throughput for a set of hosts over whole seconds [s_from, s_to]."""
    n_sent = sum(1 for h in hosts for t in sent.get(h, []) if s_from <= int(t) <= s_to)
    n_recv = sum(recv.get(h, {}).get(s, (0, 0))[0] for h in hosts for s in range(s_from, s_to + 1))
    n_bytes = sum(recv.get(h, {}).get(s, (0, 0))[1] for h in hosts for s in range(s_from, s_to + 1))
    secs = s_to - s_from + 1
    return {"sent_packets": n_sent, "received_packets": n_recv,
            "pdr": _ratio(n_recv, n_sent),
            "sent_pps": n_sent / secs if secs > 0 else None,
            "received_pps": n_recv / secs if secs > 0 else None,
            "received_kbps": n_bytes * 8 / 1000 / secs if secs > 0 else None,
            "seconds": secs}


def mitigation_metrics(events, actions, attack_iv, port_map, attack_hosts, legit_hosts):
    def ev(name):
        return [e for e in events if e["event"] == name]

    sent = ev("limit_sent")
    confirmed = ev("limit_confirmed")
    removed = ev("remove_confirmed")
    ports = sorted({int(p) for e in sent for p in e["ports"].split()})
    hosts = [port_map.get(str(p), "port%d" % p) for p in ports]
    first_applied = _float(confirmed[0]["wall_time"]) if confirmed else None
    d2a = None
    if confirmed:
        m = re.search(r"decision_to_applied_ms=([\d.]+)", confirmed[0]["detail"])
        d2a = float(m.group(1)) if m else None
    return {
        "mitigation_starts": sum(a["action"] == "start" for a in actions),
        "mitigation_active_windows": sum(a["mitigation_active"] == "1" for a in actions),
        "rate_limits_installed": len(sent),
        "openflow_rules_installed": 2 * len(sent),      # one meter + one flow per limit
        "of_errors": len(ev("of_error")),
        "no_offender_found_events": len(ev("no_offender_found")),
        "limited_hosts": hosts,
        "attack_hosts_limited": sorted(h for h in hosts if h in attack_hosts),
        "legit_hosts_limited": sorted(h for h in hosts if h in legit_hosts),
        "response_time_s": (first_applied - attack_iv[0])
        if (first_applied is not None and attack_iv is not None) else None,
        "decision_to_rule_applied_ms": d2a,
        # Release delay = first removal AFTER the attack ended. Removals before
        # the end mean mitigation was lifted while the attack still ran; that is
        # reported separately instead of as a negative delay.
        "release_delay_s": _release_delay(removed, attack_iv),
        "released_before_attack_end": (any(_float(e["wall_time"]) < attack_iv[1] for e in removed)
                                       if (removed and attack_iv is not None) else None),
    }


def _release_delay(removed, attack_iv):
    if not removed or attack_iv is None:
        return None
    after = [_float(e["wall_time"]) for e in removed if _float(e["wall_time"]) >= attack_iv[1]]
    return (after[0] - attack_iv[1]) if after else None


def evaluate_run(run_dir):
    with open(os.path.join(run_dir, "meta.json")) as f:
        meta = json.load(f)
    ip_to_host = {ip: h for h, ip in meta.get("host_ips", {}).items()}
    attack_hosts, legit_hosts = meta["attack_hosts"], meta["legit_hosts"]

    decisions = read_decisions(os.path.join(run_dir, "decisions.csv"))
    actions = _rows(os.path.join(run_dir, "actions.csv"))
    events = _rows(os.path.join(run_dir, "events.csv"))
    sent = load_sent(run_dir)
    recv = load_received(run_dir, ip_to_host)

    atk_times = [t for h in attack_hosts for t in sent.get(h, [])]
    attack_iv = (min(atk_times), max(atk_times)) if atk_times else None
    t_from = meta["t_bg_start"]
    t_to = meta.get("t_stop", meta["t_run_end"])

    m = {"run_id": meta["run_id"], "scenario": meta["scenario"],
         "attack_level": meta.get("attack_level"), "detector": meta["detector"],
         "mitigation": meta["mitigation"], "config_overrides": meta.get("config_overrides", {}),
         "duration_s": meta["t_run_end"] - meta["t_run_start"],
         "attack_interval_s": (attack_iv[1] - attack_iv[0]) if attack_iv else None}

    m["detection"] = detection_metrics(decisions, attack_iv, t_from, t_to, actions)
    m["mitigation_actions"] = mitigation_metrics(events, actions, attack_iv,
                                                 meta.get("port_map", {}),
                                                 attack_hosts, legit_hosts)

    # Traffic: whole measured period, and the attack (or scenario) interval.
    whole = (int(t_from) + 1, int(t_to) - 1)
    focus_from = attack_iv[0] if attack_iv else meta["t_scenario_start"]
    focus_to = attack_iv[1] if attack_iv else meta["t_scenario_end"]
    focus = (int(focus_from), int(focus_to))
    before = (int(t_from) + 2, int(meta["t_scenario_start"]) - 1)
    m["traffic"] = {
        "legit_whole_run": traffic_metrics(sent, recv, legit_hosts, *whole),
        "legit_before_scenario": traffic_metrics(sent, recv, legit_hosts, *before),
        "legit_during_focus": traffic_metrics(sent, recv, legit_hosts, *focus),
        "legit_bg_host_during_focus": traffic_metrics(sent, recv, [meta.get("legit_bg_host", "h6")],
                                                      *focus),
        "attack_during_focus": traffic_metrics(sent, recv, attack_hosts, *focus)
        if attack_hosts else None,
        "victim_total_during_focus": traffic_metrics(sent, recv, attack_hosts + legit_hosts, *focus),
        "focus": "attack interval" if attack_iv else "scenario interval",
    }

    samples, tx, rx = load_ping(run_dir, "h6")
    during = [r for t, r in samples if focus_from <= t <= focus_to]
    m["ping_h6"] = {"sent": tx, "received": rx,
                    "loss_pct": (100.0 * (tx - rx) / tx) if tx else None,
                    "rtt_avg_ms": _mean(r for _, r in samples),
                    "rtt_avg_during_focus_ms": _mean(during),
                    "rtt_max_during_focus_ms": max(during) if during else None}

    feats = _rows(os.path.join(run_dir, "features.csv"))
    occ = [_float(r["FlowTableOccupancy"]) for r in feats if _float(r["FlowTableOccupancy"]) is not None]
    pin = [(_float(r["timestamp"]), _float(r["PacketInRate"]) or 0.0) for r in feats]
    m["switch"] = {
        "flow_table_max_entries": max(occ) if occ else None,
        "flow_table_mean_entries": _mean(occ),
        "packet_in_total": sum(v for _, v in pin),       # PacketInRate x 1 s window
        "packet_in_during_focus": sum(v for t, v in pin if t is not None and
                                      focus_from <= t - LAG_S <= focus_to),
        "window_s": 1,
    }

    # The switch's own view (ovs.csv, sampled by run_experiment.py with ovs-ofctl);
    # absent in runs recorded before this sampler existed -> None, not 0.
    ovs = _rows(os.path.join(run_dir, "ovs.csv"))
    ints = lambda col: [int(r[col]) for r in ovs if r.get(col, "").isdigit()]
    m["switch_view"] = {
        "samples": len(ovs),
        "max_m4_flows_on_switch": max(ints("m4_flows")) if ovs else None,
        "max_meters_on_switch": max(ints("meters")) if ovs else None,
        "meter_packets_dropped_max": max(ints("meter_packets_dropped")) if ovs else None,
        "m4_flows_at_end": ints("m4_flows")[-1] if ovs else None,
    }

    res = defaultdict(lambda: {"cpu": [], "rss": []})
    for r in _rows(os.path.join(run_dir, "resources.csv")):
        res[r["name"]]["cpu"].append(float(r["cpu_percent"]))
        res[r["name"]]["rss"].append(float(r["rss_mb"]))
    m["resources"] = {name: {"cpu_mean_pct": _mean(v["cpu"]), "cpu_max_pct": max(v["cpu"]),
                             "rss_mean_mib": _mean(v["rss"]), "rss_max_mib": max(v["rss"]),
                             "samples": len(v["cpu"])}
                      for name, v in res.items() if v["cpu"]}
    return m


def write_metrics(run_dir, metrics):
    with open(os.path.join(run_dir, METRICS_FILE), "w") as f:
        json.dump(metrics, f, indent=2)


def _fmt(v, nd=3):
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return ("%." + str(nd) + "f") % v
    return str(v)


def format_summary(m):
    d, a, t = m["detection"], m["mitigation_actions"], m["traffic"]
    lines = ["", "=== %s ===" % m["run_id"],
             "detection : TP=%d FP=%d FN=%d TN=%d  precision=%s recall=%s F1=%s FPR=%s  latency=%s s"
             % (d["tp"], d["fp"], d["fn"], d["tn"], _fmt(d["precision"]), _fmt(d["recall"]),
                _fmt(d["f1"]), _fmt(d["fpr"]), _fmt(d["detection_latency_s"], 1)),
             "mitigation: starts=%d limits=%d hosts=%s (legit limited: %s) response=%s s release=%s s%s errors=%d"
             % (a["mitigation_starts"], a["rate_limits_installed"], a["limited_hosts"] or "-",
                a["legit_hosts_limited"] or "none", _fmt(a["response_time_s"], 2),
                _fmt(a["release_delay_s"], 2),
                " (released before attack end!)" if a.get("released_before_attack_end") else "",
                a["of_errors"]),
             "traffic (%s): legit PDR=%s (before: %s)  legit rx=%s pkt/s" % (
                 t["focus"], _fmt(t["legit_during_focus"]["pdr"]),
                 _fmt(t["legit_before_scenario"]["pdr"]), _fmt(t["legit_during_focus"]["received_pps"], 1))]
    if t["attack_during_focus"]:
        lines.append("            attack PDR=%s  attack rx=%s pkt/s (sent %s pkt/s)" % (
            _fmt(t["attack_during_focus"]["pdr"]), _fmt(t["attack_during_focus"]["received_pps"], 1),
            _fmt(t["attack_during_focus"]["sent_pps"], 1)))
    p, s = m["ping_h6"], m["switch"]
    lines.append("ping h6   : loss=%s%% rtt avg=%s ms (during: %s ms)" % (
        _fmt(p["loss_pct"], 1), _fmt(p["rtt_avg_ms"]), _fmt(p["rtt_avg_during_focus_ms"])))
    lines.append("switch    : flow entries max=%s  Packet-In total=%s (during: %s)" % (
        _fmt(s["flow_table_max_entries"], 0), _fmt(s["packet_in_total"], 0),
        _fmt(s["packet_in_during_focus"], 0)))
    v = m.get("switch_view") or {}
    if v.get("samples"):
        lines.append("ovs-ofctl : our flows max=%s meters max=%s  meter-dropped packets=%s  our flows at end=%s" % (
            v["max_m4_flows_on_switch"], v["max_meters_on_switch"], v["meter_packets_dropped_max"],
            v["m4_flows_at_end"]))
    for name, r in sorted(m["resources"].items()):
        lines.append("%-10s: CPU mean=%s%% max=%s%%  RSS max=%s MiB" % (
            name, _fmt(r["cpu_mean_pct"], 1), _fmt(r["cpu_max_pct"], 1), _fmt(r["rss_max_mib"], 1)))
    lines.append("duration  : %s s" % _fmt(m["duration_s"], 1))
    return "\n".join(lines)


if __name__ == "__main__":
    for run in sys.argv[1:]:
        metrics = evaluate_run(run)
        write_metrics(run, metrics)
        print(format_summary(metrics))

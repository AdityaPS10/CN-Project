"""Member 4 dashboard - builds one JSON snapshot of a run folder. READ-ONLY.

It only opens files for reading (meta.json, decisions.csv, actions.csv,
events.csv, port_stats.csv, sink.csv, resources.csv) - the same files the
controller, detector and sink write anyway. It never writes, never talks to
the controller or switch, and never raises: anything unreadable becomes an
entry in `warnings` and the rest of the snapshot is still returned.

Files that are still being written are handled: a half-written last line is
ignored until it is complete.
"""
import csv
import io
import json
import os
import re
import time

LIVE_WINDOW_S = 120          # a running run shows the last 2 minutes
ATTACK = {"naive_ddos", "adaptive_ddos"}

_cache = {}                  # path -> (mtime, size, rows)


def _read_rows(path, warnings):
    """All complete CSV rows as dicts; [] if the file does not exist yet."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return []
    except OSError as e:
        warnings.append("%s: %s" % (os.path.basename(path), e))
        return []
    hit = _cache.get(path)
    if hit and hit[0] == st.st_mtime and hit[1] == st.st_size:
        return hit[2]
    try:
        with open(path, "rb") as f:
            data = f.read()
        end = data.rfind(b"\n")
        text = data[:end + 1].decode("utf-8", "replace") if end >= 0 else ""
        rows = list(csv.DictReader(io.StringIO(text)))
    except Exception as e:                       # noqa: BLE001 - never crash
        warnings.append("%s: %s" % (os.path.basename(path), e))
        return hit[2] if hit else []
    _cache[path] = (st.st_mtime, st.st_size, rows)
    return rows


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def list_runs(results_dir):
    """Run folders, newest first: [{id, status}]."""
    runs = []
    try:
        names = sorted(os.listdir(results_dir), reverse=True)
    except OSError:
        return runs
    for name in names:
        d = os.path.join(results_dir, name)
        if not os.path.isdir(d):
            continue
        status = "finished"
        try:
            with open(os.path.join(d, "meta.json")) as f:
                status = json.load(f).get("status", "finished")
        except (OSError, ValueError):
            status = "starting"
        runs.append({"id": name, "status": status})
    return runs


def build_state(run_dir, decisions_fallback=None, now=None):
    warnings = []
    now = time.time() if now is None else now
    meta = {}
    try:
        with open(os.path.join(run_dir, "meta.json")) as f:
            meta = json.load(f)
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as e:
        warnings.append("meta.json: %s" % e)

    p = lambda name: os.path.join(run_dir, name)
    dec_path = p("decisions.csv")
    if not os.path.exists(dec_path) and decisions_fallback:
        dec_path = decisions_fallback
    decisions = _read_rows(dec_path, warnings)
    actions = _read_rows(p("actions.csv"), warnings)
    events = _read_rows(p("events.csv"), warnings)
    ports = _read_rows(p("port_stats.csv"), warnings)
    sink = _read_rows(p("sink.csv"), warnings)
    res = _read_rows(p("resources.csv"), warnings)

    status = meta.get("status") or ("finished" if "t_run_end" in meta else
                                    ("running" if events else "waiting"))
    live = status in ("starting", "running", "waiting")

    # Time origin: run start; fallback to the first timestamp we can find.
    t0 = _f(meta.get("t_run_start"))
    if t0 is None:
        firsts = [_f(r.get("wall_time")) for r in events[:1] + ports[:1]]
        firsts = [x for x in firsts if x is not None]
        t0 = min(firsts) if firsts else now
    t_end = _f(meta.get("t_run_end")) if not live else now
    t_end = t_end if t_end is not None else now
    t_from = max(t0, t_end - LIVE_WINDOW_S) if live else t0
    rel = lambda t: round(t - t0, 2)

    port_map = meta.get("port_map") or {}
    host_of = lambda port: port_map.get(str(port), "port%s" % port)
    ip_host = {ip: h for h, ip in (meta.get("host_ips") or {}).items()}
    server = meta.get("server", "h1")
    roles = {}
    for h in meta.get("legit_hosts", []):
        roles[h] = "legitimate"
    for h in meta.get("attack_hosts", []):
        roles[h] = "attacker"

    # ---- per-host series -------------------------------------------------
    port_rate = {}
    for r in ports:
        t, pps = _f(r.get("wall_time")), _f(r.get("rx_pps"))
        if t is None or pps is None or t < t_from:
            continue
        h = host_of(r.get("port"))
        if h == server:
            continue
        port_rate.setdefault(h, []).append([rel(t), round(pps, 1)])

    # The sink writes a row only for seconds in which something arrived, so a
    # second with no row means 0 packets: fill those, or a pausing attacker's
    # line would be drawn straight across its pause.
    per_sec, secs = {}, set()
    for r in sink:
        s = _f(r.get("second"))
        if s is None or s + 1 < t_from:
            continue
        s = int(s)
        h = ip_host.get(r.get("src_ip"), r.get("src_ip"))
        per_sec.setdefault(h, {})[s] = int(_f(r.get("packets")) or 0)
        secs.add(s)
    victim_rx = {}
    if secs:
        span = range(min(secs), max(secs) + 1)
        for h, counts in per_sec.items():
            victim_rx[h] = [[rel(s + 1), counts.get(s, 0)] for s in span]

    hosts = sorted(set(port_rate) | set(victim_rx) | set(roles),
                   key=lambda h: (len(h), h))

    # ---- decisions -------------------------------------------------------
    dec_rows = []
    for r in decisions:
        t = _f(r.get("timestamp"))
        if t is None or t < t_from:
            continue
        dec_rows.append({"t": rel(t), "cls": r.get("traffic_class", ""),
                         "rule": r.get("rule", ""), "score": _f(r.get("score")),
                         "reason": r.get("reason", "")})
    latest = dec_rows[-1] if dec_rows else None

    # ---- mitigation state ------------------------------------------------
    spans, start = [], None
    for r in actions:
        t = _f(r.get("wall_time"))
        if t is None:
            continue
        if r.get("action") == "start":
            start = t
        elif r.get("action") == "stop" and start is not None:
            spans.append([rel(start), rel(t)])
            start = None
    if start is not None:
        spans.append([rel(start), None])
    spans = [s for s in spans if s[1] is None or s[1] >= rel(t_from)]
    active = bool(actions) and actions[-1].get("mitigation_active") == "1"

    limited, cfg = set(), {}
    for r in events:
        ev = r.get("event")
        hs = [host_of(x) for x in (r.get("ports") or "").split()]
        if ev == "limit_sent":
            limited.update(hs)
        elif ev in ("remove_sent", "switch_connected", "switch_disconnected"):
            limited.clear()
        elif ev == "app_started":
            cfg = dict(kv.split("=", 1) for kv in (r.get("detail") or "").split() if "=" in kv)
    ev_list = []
    for r in events[-14:]:
        t = _f(r.get("wall_time"))
        ev_list.append({"t": rel(t) if t is not None else None, "event": r.get("event", ""),
                        "hosts": [host_of(x) for x in (r.get("ports") or "").split()],
                        "detail": r.get("detail", "")})

    # ---- resources -------------------------------------------------------
    resources = {}
    for r in res:
        resources[r.get("name", "?")] = {"cpu_pct": _f(r.get("cpu_percent")),
                                         "rss_mib": _f(r.get("rss_mb"))}

    phases = {}
    for key in ("t_bg_start", "t_scenario_start", "t_scenario_end", "t_stop"):
        if _f(meta.get(key)) is not None:
            phases[key[2:]] = rel(_f(meta[key]))

    return {
        "run": {"id": meta.get("run_id") or os.path.basename(os.path.normpath(run_dir)),
                "scenario": meta.get("scenario"), "attack_level": meta.get("attack_level"),
                "detector": meta.get("detector"), "mitigation": meta.get("mitigation"),
                "status": status, "live": live, "elapsed_s": rel(t_end),
                "x_from": rel(t_from), "x_to": rel(t_end), "phases": phases},
        "hosts": [{"name": h, "role": roles.get(h, "idle")} for h in hosts],
        "series": {"port_rate": port_rate, "victim_rx": victim_rx},
        "decision": latest,
        "decisions": dec_rows,
        "mitigation": {"active": active, "spans": spans,
                       "limited": sorted(limited, key=lambda h: (len(h), h)),
                       "meter_rate_pps": _f(cfg.get("meter_rate_pps")),
                       "offender_min_pps": _f(cfg.get("offender_min_pps")),
                       "enforcement": cfg.get("enforcement")},
        "events": ev_list,
        "resources": resources,
        "totals": {"windows": len(decisions),
                   "attack_windows": sum(r.get("traffic_class") in ATTACK for r in decisions),
                   "limits_installed": sum(r.get("event") == "limit_sent" for r in events),
                   "of_errors": sum(r.get("event") == "of_error" for r in events)},
        "warnings": warnings,
        "generated_at": now,
    }


_SAFE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def safe_run_dir(results_dir, run_id):
    """Resolve a run id from the browser to a folder INSIDE results_dir, or None."""
    if not run_id or not _SAFE.match(run_id) or run_id in (".", ".."):
        return None
    d = os.path.join(results_dir, run_id)
    return d if os.path.isdir(d) else None

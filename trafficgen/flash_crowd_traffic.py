#!/usr/bin/env python3
"""
Step 4: Genuine flash-crowd traffic generator.

Simulates several independent "virtual users" originating from ONE
physical Mininet host, each behaving like Step 3's normal traffic
(steady rate + small jitter) but with:
  - a randomized own packet rate (heterogeneous clients)
  - a randomized start time within a ramp-up window (staggered arrival)
so the AGGREGATE load organically grows as more virtual users come
online, then holds at an elevated level -- a real flash crowd's shape --
without any central coordination, evasion logic, or artificial pauses.
Each virtual user is logically a separate flow with its own flow_id.

Run (inside Mininet, from the CLI, after the server is listening on h1):
    mininet> h2 python3 trafficgen/flash_crowd_traffic.py \
                 --src-name=h2 --dst-name=h1 --dst-ip=10.0.0.1 \
                 --num-flows=4 --ramp-up=10 --hold=15 \
                 --rate-min=5 --rate-max=15 --log=logs/flash_h2.csv &

Run this on several hosts (h2..h6) at once to see the full flash-crowd
effect converge on h1.
"""
import argparse
import random
import socket
import threading
import time
import uuid

from common import CsvLogger

# Shared across all virtual-user threads in THIS process (one physical host).
_active_lock = threading.Lock()
_active_flows = 0


def _flow_started():
    global _active_flows
    with _active_lock:
        _active_flows += 1
        return _active_flows


def _flow_ended():
    global _active_flows
    with _active_lock:
        _active_flows -= 1


def _active_count():
    with _active_lock:
        return _active_flows


def virtual_user(index, src_name, dst_name, dst_ip, dst_port, start_offset,
                  run_duration, rate_pps, jitter_frac, pkt_size, logger):
    time.sleep(start_offset)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flow_id = "flash-%s-%s-u%d-%s" % (src_name, dst_name, index, uuid.uuid4().hex[:8])
    payload = b"F" * pkt_size
    base_interval = 1.0 / rate_pps

    _flow_started()
    end_time = time.time() + run_duration
    last_send = time.time()
    sent = 0
    try:
        while time.time() < end_time:
            jitter = random.uniform(-jitter_frac, jitter_frac) * base_interval
            time.sleep(max(0.0, base_interval + jitter))

            now = time.time()
            inter_arrival = now - last_send
            last_send = now

            sock.sendto(payload, (dst_ip, dst_port))
            sent += 1

            logger.log(
                timestamp=round(now, 6),
                scenario="flash_crowd",
                source_host=src_name,
                destination_host=dst_name,
                packet_rate=round(rate_pps, 3),
                flow_rate=_active_count(),
                inter_arrival_time=round(inter_arrival, 6),
                jitter=round(jitter, 6),
                flow_id=flow_id,
                attack_level="none",
                feint_state="none",
            )
    finally:
        _flow_ended()
        print("[%s] virtual user %d sent %d packets" % (src_name, index, sent))


def run(src_name, dst_name, dst_ip, dst_port, num_flows, ramp_up, hold,
        rate_min, rate_max, jitter_frac, pkt_size, log_path):
    logger = CsvLogger(log_path)
    threads = []

    for i in range(num_flows):
        start_offset = random.uniform(0, ramp_up)
        # Each virtual user runs until the shared global end time, so
        # arrivals stagger in but the crowd stays elevated together,
        # then (roughly) disperses together -- a real flash-crowd shape.
        run_duration = (ramp_up - start_offset) + hold
        rate_pps = random.uniform(rate_min, rate_max)

        t = threading.Thread(target=virtual_user, args=(
            i, src_name, dst_name, dst_ip, dst_port, start_offset,
            run_duration, rate_pps, jitter_frac, pkt_size, logger))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    logger.close()
    print("[%s] flash-crowd scenario done: %d virtual users, log: %s"
          % (src_name, num_flows, log_path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-name", required=True)
    ap.add_argument("--dst-name", required=True)
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--dst-port", type=int, default=5000)
    ap.add_argument("--num-flows", type=int, default=4,
                     help="virtual users to simulate from this host")
    ap.add_argument("--ramp-up", type=float, default=10.0,
                     help="seconds over which virtual users stagger their start")
    ap.add_argument("--hold", type=float, default=15.0,
                     help="seconds the crowd stays elevated after ramp-up completes")
    ap.add_argument("--rate-min", type=float, default=5.0)
    ap.add_argument("--rate-max", type=float, default=15.0)
    ap.add_argument("--jitter", type=float, default=0.15)
    ap.add_argument("--pkt-size", type=int, default=128)
    ap.add_argument("--log", default="logs/flash_crowd.csv")
    args = ap.parse_args()

    run(args.src_name, args.dst_name, args.dst_ip, args.dst_port,
        args.num_flows, args.ramp_up, args.hold,
        args.rate_min, args.rate_max, args.jitter, args.pkt_size, args.log)


if __name__ == "__main__":
    main()

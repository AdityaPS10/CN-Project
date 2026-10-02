#!/usr/bin/env python3
"""
Step 3: Normal traffic generator.

Simulates one well-behaved client: a single flow, a steady target packet
rate, and small natural jitter (real end-user traffic is never perfectly
periodic -- OS scheduling, app think-time, etc. add small random variance,
typically a few percent to ~20% of the base interval). No ramp-up, no
bursts, no new-flow creation, no feints -- those are what will make the
LATER scenarios (flash crowd, DDoS, adaptive DDoS) distinguishable from
this baseline.

Run (inside Mininet, from the CLI, after the server is listening on h1):
    mininet> h2 python3 trafficgen/normal_traffic.py \
                 --src-name h2 --dst-name h1 --dst-ip 10.0.0.1 \
                 --rate 10 --duration 20 --log logs/normal_h2.csv &
"""
import argparse
import random
import socket
import time
import uuid

from common import CsvLogger


def run(src_name, dst_name, dst_ip, dst_port, rate_pps, jitter_frac,
        pkt_size, duration, log_path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger = CsvLogger(log_path)
    flow_id = "normal-%s-%s-%s" % (src_name, dst_name, uuid.uuid4().hex[:8])
    payload = b"N" * pkt_size
    base_interval = 1.0 / rate_pps

    end_time = time.time() + duration
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
                scenario="normal",
                source_host=src_name,
                destination_host=dst_name,
                packet_rate=rate_pps,
                flow_rate=1,
                inter_arrival_time=round(inter_arrival, 6),
                jitter=round(jitter, 6),
                flow_id=flow_id,
                attack_level="none",
                feint_state="none",
            )
    finally:
        logger.close()
        print("[%s] sent %d packets to %s (%s) -> log: %s"
              % (src_name, sent, dst_name, dst_ip, log_path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-name", required=True, help="this host's Mininet name, e.g. h2")
    ap.add_argument("--dst-name", required=True, help="destination's Mininet name, e.g. h1")
    ap.add_argument("--dst-ip", required=True, help="destination IP, e.g. 10.0.0.1")
    ap.add_argument("--dst-port", type=int, default=5000)
    ap.add_argument("--rate", type=float, default=10.0, help="target packets/sec")
    ap.add_argument("--jitter", type=float, default=0.15,
                     help="fractional jitter, e.g. 0.15 = +/-15%% of interval")
    ap.add_argument("--pkt-size", type=int, default=128, help="UDP payload bytes")
    ap.add_argument("--duration", type=float, default=30.0, help="seconds to run")
    ap.add_argument("--log", default="logs/normal_traffic.csv")
    args = ap.parse_args()

    run(args.src_name, args.dst_name, args.dst_ip, args.dst_port,
        args.rate, args.jitter, args.pkt_size, args.duration, args.log)


if __name__ == "__main__":
    main()

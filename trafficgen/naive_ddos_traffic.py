#!/usr/bin/env python3
"""
Step 5: Naive low-rate DDoS generator.

Deliberately crude, by design: this is the "easy to catch" attack
baseline, so Step 6's adaptive attack has something to meaningfully
evade. Signature properties, in contrast to normal/flash-crowd traffic:

  - near-zero jitter -> packets arrive almost perfectly periodically
    (real traffic, Steps 3-4, is never this regular)
  - synchronized onset -> every attacker host starts at the same instant
    (no staggered arrival like a real flash crowd)
  - homogeneous rate -> every flow uses the SAME fixed low rate
    (real users have a natural spread of rates)
  - one flow per host, continuous for the whole run -> no new-flow
    creation, no variation, no pauses (pauses/feints come in Step 8)

"Low-rate" = low enough per flow to try to sit under a naive fixed
per-flow rate-limit threshold, while still adding up to a meaningful
load on the victim once several attacker hosts run it together.

Run (inside Mininet, from the CLI, after the server is listening on h1):
    mininet> h2 python3 trafficgen/naive_ddos_traffic.py \
                 --src-name=h2 --dst-name=h1 --dst-ip=10.0.0.1 \
                 --rate=8 --duration=20 --log=logs/naive_h2.csv &

Run the same command (same --rate, same --duration, no stagger) on
several hosts at once to see the flat, synchronized flood shape.
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
    flow_id = "naive-%s-%s-%s" % (src_name, dst_name, uuid.uuid4().hex[:8])
    payload = b"D" * pkt_size
    base_interval = 1.0 / rate_pps

    end_time = time.time() + duration
    last_send = time.time()
    sent = 0

    try:
        while time.time() < end_time:
            # jitter_frac defaults to 0: near-perfectly periodic, the
            # naive attack's main tell. Kept configurable only so you
            # can later demonstrate how a *little* jitter already
            # starts to defeat simple periodicity-based detectors.
            jitter = random.uniform(-jitter_frac, jitter_frac) * base_interval if jitter_frac else 0.0
            time.sleep(max(0.0, base_interval + jitter))

            now = time.time()
            inter_arrival = now - last_send
            last_send = now

            sock.sendto(payload, (dst_ip, dst_port))
            sent += 1

            logger.log(
                timestamp=round(now, 6),
                scenario="naive_ddos",
                source_host=src_name,
                destination_host=dst_name,
                packet_rate=rate_pps,
                flow_rate=1,
                inter_arrival_time=round(inter_arrival, 6),
                jitter=round(jitter, 6),
                flow_id=flow_id,
                attack_level="naive",
                feint_state="none",
            )
    finally:
        logger.close()
        print("[%s] naive DDoS sent %d packets to %s (%s) -> log: %s"
              % (src_name, sent, dst_name, dst_ip, log_path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-name", required=True)
    ap.add_argument("--dst-name", required=True)
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--dst-port", type=int, default=5000)
    ap.add_argument("--rate", type=float, default=8.0,
                     help="fixed packets/sec, identical across all attacker hosts")
    ap.add_argument("--jitter", type=float, default=0.0,
                     help="fractional jitter; 0.0 = perfectly periodic (the naive signature)")
    ap.add_argument("--pkt-size", type=int, default=128)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--log", default="logs/naive_ddos.csv")
    args = ap.parse_args()

    run(args.src_name, args.dst_name, args.dst_ip, args.dst_port,
        args.rate, args.jitter, args.pkt_size, args.duration, args.log)


if __name__ == "__main__":
    main()

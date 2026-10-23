#!/usr/bin/env python3
"""Member 4 - measuring UDP sink for the victim host (h1).

Same job as trafficgen/server.py (receive and discard, so senders get no
ICMP port-unreachable), but it also records what actually ARRIVED:
one CSV row per (second, source IP) with packet and payload-byte counts.
Comparing this with Member 1's per-packet send logs gives delivery ratio
and throughput per host.

    h1 python3 member4_mitigation/sink.py --port=5000 --out=results/<run>/sink.csv &

Stops cleanly (flushing the last second) on SIGINT or SIGTERM.
"""
import argparse
import csv
import signal
import socket
import time
from collections import defaultdict


class SecondCounter:
    """Counts packets/bytes per (whole second, source); emits finished seconds."""

    def __init__(self):
        self.counts = defaultdict(lambda: [0, 0])     # (sec, src) -> [packets, bytes]

    def add(self, t, src, nbytes):
        c = self.counts[(int(t), src)]
        c[0] += 1
        c[1] += nbytes

    def pop_before(self, sec):
        """Remove and return rows for seconds < sec, sorted."""
        done = sorted(k for k in self.counts if k[0] < sec)
        return [(s, src, *self.counts.pop((s, src))) for s, src in done]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.2)
    counter = SecondCounter()

    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["second", "src_ip", "packets", "bytes"])
        fh.flush()
        print("[sink] listening UDP %s:%d -> %s" % (args.bind, args.port, args.out), flush=True)
        while not stop:
            try:
                data, addr = sock.recvfrom(65535)
                counter.add(time.time(), addr[0], len(data))
            except socket.timeout:
                pass
            except InterruptedError:
                pass
            rows = counter.pop_before(int(time.time()))
            if rows:
                w.writerows(rows)
                fh.flush()
        w.writerows(counter.pop_before(float("inf")))
    print("[sink] stopped", flush=True)


if __name__ == "__main__":
    main()

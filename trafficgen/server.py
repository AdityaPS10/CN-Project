#!/usr/bin/env python3
"""
Minimal UDP sink server. Run this on the "server"/victim host (h1) before
starting any traffic generator script. It just receives and discards
packets, printing a running count -- its only job is to stop every sent
packet from bouncing back as an ICMP port-unreachable, which would
otherwise pollute the traffic you're trying to generate/measure.

Run (inside Mininet, from the CLI):
    mininet> h1 python3 trafficgen/server.py --port 5000 &
"""
import argparse
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print("[server] listening UDP %s:%d" % (args.bind, args.port), flush=True)

    count = 0
    start = time.time()
    while True:
        data, addr = sock.recvfrom(65535)
        count += 1
        if count % 50 == 0:
            elapsed = time.time() - start
            print("[server] received %d packets (last from %s:%d, %.1fs elapsed)"
                  % (count, addr[0], addr[1], elapsed), flush=True)


if __name__ == "__main__":
    main()

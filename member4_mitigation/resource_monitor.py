#!/usr/bin/env python3
"""Member 4 - samples CPU and memory of controller-side processes.

Uses psutil (system package python3-psutil). Each sample row:
    wall_time, name, pid, cpu_percent, rss_mb
cpu_percent: % of ONE core used since the previous sample (can exceed 100
on multiple cores). rss_mb: resident memory in MiB (1 MiB = 2**20 bytes).

Used as a thread by run_experiment.py, or standalone:
    python3 member4_mitigation/resource_monitor.py --pid controller=1234 --out res.csv
"""
import argparse
import csv
import threading
import time

import psutil


class ResourceMonitor(threading.Thread):
    def __init__(self, targets, out_path, interval=1.0):
        """targets: dict name -> pid"""
        super().__init__(daemon=True)
        self.interval = interval
        self.out_path = out_path
        self._halt = threading.Event()
        self.procs = {}
        for name, pid in targets.items():
            p = psutil.Process(pid)
            p.cpu_percent(None)          # first call only sets the reference point
            self.procs[name] = p

    def run(self):
        with open(self.out_path, "w", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["wall_time", "name", "pid", "cpu_percent", "rss_mb"])
            while not self._halt.wait(self.interval):
                now = time.time()
                for name, p in self.procs.items():
                    try:
                        with p.oneshot():
                            cpu = p.cpu_percent(None)
                            rss = p.memory_info().rss / 2 ** 20
                    except psutil.Error:
                        continue        # process ended
                    w.writerow(["%.3f" % now, name, p.pid, "%.1f" % cpu, "%.2f" % rss])
                fh.flush()

    def stop(self):
        self._halt.set()
        self.join(timeout=5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", action="append", required=True, help="name=pid, repeatable")
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()
    targets = {k: int(v) for k, v in (x.split("=", 1) for x in args.pid)}
    mon = ResourceMonitor(targets, args.out, args.interval)
    mon.start()
    try:
        while mon.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        mon.stop()


if __name__ == "__main__":
    main()

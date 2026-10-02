"""
Shared logging interface for ALL Member 1 traffic/attack scenarios.

This is the contract Member 2 depends on. Every scenario script (normal,
flash crowd, naive DDoS, adaptive DDoS) writes rows with this exact set of
columns, regardless of its internal logic. Member 2 should only ever need
to read these CSV files -- never Member 1's generator code.

Columns:
    timestamp          float, unix epoch seconds, when the packet was sent
    scenario            str, one of: normal | flash_crowd | naive_ddos | adaptive_ddos
    source_host         str, Mininet host name, e.g. "h2"
    destination_host    str, Mininet host name, e.g. "h1"
    packet_rate         float, target packets/sec configured for this flow
    flow_rate           int, number of concurrent flows this source is running
    inter_arrival_time  float, seconds since this source's previous packet
    jitter              float, seconds of jitter applied to this packet's wait
    flow_id             str, unique id per logical flow (lets Member 2 group rows)
    attack_level        str, one of: none | naive | subtle | moderate | aggressive
    feint_state         str, one of: none | attack | pause  (used from Step 8 on)

Each generator process gets its OWN log file (passed via --log), rather
than all processes sharing one file, to avoid any risk of interleaved
writes corrupting rows when many hosts run at once. Member 2's module
should read every file under logs/ matching logs/*.csv.

See docs/MEMBER1_INTERFACE.md for the full, human-readable spec
(valid value sets, file layout, the JSON sidecar format, and known
caveats like pauses appearing as gaps rather than rows).
"""
import csv
import os
import threading

CSV_FIELDS = [
    "timestamp",
    "scenario",
    "source_host",
    "destination_host",
    "packet_rate",
    "flow_rate",
    "inter_arrival_time",
    "jitter",
    "flow_id",
    "attack_level",
    "feint_state",
]

# Single source of truth for valid values -- imported by validate_log.py
# so the validator can never silently drift out of sync with this module.
SCENARIOS = ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos"]
ATTACK_LEVELS = ["none", "naive", "subtle", "moderate", "aggressive"]
FEINT_STATES = ["none", "attack", "pause"]


class CsvLogger:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        is_new = not os.path.exists(path) or os.path.getsize(path) == 0
        self._fh = open(path, "a", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_FIELDS)
        if is_new:
            self._writer.writeheader()
            self._fh.flush()

    def log(self, **kwargs):
        row = {k: kwargs.get(k, "") for k in CSV_FIELDS}
        with self._lock:
            self._writer.writerow(row)
            self._fh.flush()

    def close(self):
        self._fh.close()

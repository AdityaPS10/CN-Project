#!/usr/bin/env python3
"""
Step 9: Log validator for Member 1's traffic-generation interface.

Member 2 (or anyone) can run this against any CSV produced by the
scenario scripts in this folder to sanity-check it matches the schema
in docs/MEMBER1_INTERFACE.md / common.py, BEFORE spending time writing
analysis code against it. Catches the kind of mistake that silently
corrupts downstream results, e.g. a host-name field that got mangled
into an IP address (see the Mininet CLI substitution caveat in the docs).

Usage:
    python3 trafficgen/validate_log.py logs/normal_h2.csv
    python3 trafficgen/validate_log.py logs/*.csv          # validate several at once
    python3 trafficgen/validate_log.py logs/*.csv --strict # non-zero exit on ANY warning

Checks performed, per file:
    1. Header matches CSV_FIELDS exactly (right columns, right order).
    2. Every row has all fields non-empty (no silently-dropped values).
    3. timestamp, packet_rate, flow_rate, inter_arrival_time, jitter
       all parse as numbers.
    4. flow_rate is a non-negative integer.
    5. scenario / attack_level / feint_state are each from the allowed
       value sets in common.py (catches typos like "flashcrowd").
    6. source_host / destination_host look like Mininet host names
       (e.g. "h2"), NOT IP addresses -- the #1 real mistake this project
       hit (Mininet's CLI silently substitutes bare host-name tokens
       with IPs; see docs/MEMBER1_INTERFACE.md).
    7. Within each flow_id, timestamps are monotonically non-decreasing.
    8. Rows are sorted by timestamp overall (just a warning, not fatal --
       per-process files are written in send order, which IS time order,
       but concatenating multiple files before validating will not be).
"""
import argparse
import csv
import re
import sys

from common import CSV_FIELDS, SCENARIOS, ATTACK_LEVELS, FEINT_STATES

IP_LIKE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
HOST_LIKE = re.compile(r"^h\d+$")


def validate_file(path):
    errors = []
    warnings = []

    try:
        f = open(path, newline="")
    except OSError as e:
        return [f"cannot open file: {e}"], []

    with f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return ["file is empty, no header row"], []

        if header != CSV_FIELDS:
            errors.append("header mismatch:\n  expected: %s\n  found:    %s"
                           % (CSV_FIELDS, header))
            return errors, warnings  # can't trust row parsing past this

        last_ts_by_flow = {}
        prev_ts_overall = None
        max_backwards_jump = 0.0
        row_count = 0

        for lineno, row in enumerate(reader, start=2):
            row_count += 1
            if len(row) != len(CSV_FIELDS):
                errors.append("line %d: wrong number of fields (%d, expected %d)"
                               % (lineno, len(row), len(CSV_FIELDS)))
                continue
            rec = dict(zip(CSV_FIELDS, row))

            for field in CSV_FIELDS:
                if rec[field] == "":
                    errors.append("line %d: empty value for '%s'" % (lineno, field))

            try:
                ts = float(rec["timestamp"])
            except ValueError:
                errors.append("line %d: timestamp '%s' is not a number" % (lineno, rec["timestamp"]))
                ts = None

            for numfield in ("packet_rate", "inter_arrival_time", "jitter"):
                try:
                    float(rec[numfield])
                except ValueError:
                    errors.append("line %d: %s '%s' is not a number"
                                   % (lineno, numfield, rec[numfield]))

            try:
                fr = int(rec["flow_rate"])
                if fr < 0:
                    errors.append("line %d: flow_rate is negative (%d)" % (lineno, fr))
            except ValueError:
                errors.append("line %d: flow_rate '%s' is not an integer" % (lineno, rec["flow_rate"]))

            if rec["scenario"] not in SCENARIOS:
                errors.append("line %d: scenario '%s' not in %s" % (lineno, rec["scenario"], SCENARIOS))
            if rec["attack_level"] not in ATTACK_LEVELS:
                errors.append("line %d: attack_level '%s' not in %s" % (lineno, rec["attack_level"], ATTACK_LEVELS))
            if rec["feint_state"] not in FEINT_STATES:
                errors.append("line %d: feint_state '%s' not in %s" % (lineno, rec["feint_state"], FEINT_STATES))

            for hostfield in ("source_host", "destination_host"):
                val = rec[hostfield]
                if IP_LIKE.match(val):
                    errors.append(
                        "line %d: %s = '%s' looks like an IP address, not a host name. "
                        "This is the Mininet CLI host-name-substitution bug -- re-generate "
                        "this log using --opt=value syntax instead of --opt value. "
                        "See docs/MEMBER1_INTERFACE.md." % (lineno, hostfield, val))
                elif not HOST_LIKE.match(val):
                    warnings.append("line %d: %s = '%s' doesn't look like a Mininet host name (e.g. 'h2')"
                                     % (lineno, hostfield, val))

            if ts is not None:
                fid = rec["flow_id"]
                if fid in last_ts_by_flow and ts < last_ts_by_flow[fid]:
                    errors.append("line %d: timestamp went backwards within flow_id '%s' (%.6f < %.6f)"
                                   % (lineno, fid, ts, last_ts_by_flow[fid]))
                last_ts_by_flow[fid] = ts

                if prev_ts_overall is not None and ts < prev_ts_overall:
                    max_backwards_jump = max(max_backwards_jump, prev_ts_overall - ts)
                prev_ts_overall = ts

        if row_count == 0:
            warnings.append("file has a header but zero data rows")
        if max_backwards_jump > 0:
            if max_backwards_jump < 0.05:
                warnings.append(
                    "rows not globally sorted by timestamp, max backwards jump %.4fs -- "
                    "harmless: this generator runs multiple threads (virtual users/worker "
                    "flows) writing to one shared logger, so sub-50ms interleaving around "
                    "the write lock is expected. Each flow_id's own timestamps are still "
                    "checked separately above and were fine." % max_backwards_jump)
            else:
                warnings.append(
                    "rows not globally sorted by timestamp, max backwards jump %.3fs -- "
                    "this is larger than expected thread-scheduling jitter (>50ms); worth "
                    "double-checking this file wasn't concatenated from multiple runs or "
                    "clocks weren't adjusted mid-run." % max_backwards_jump)

    return errors, warnings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="CSV log file(s) to validate")
    ap.add_argument("--strict", action="store_true",
                     help="exit non-zero on warnings too, not just errors")
    args = ap.parse_args()

    any_errors = False
    any_warnings = False

    for path in args.files:
        errors, warnings = validate_file(path)
        status = "FAIL" if errors else ("WARN" if warnings else "PASS")
        print("=== %s: %s ===" % (path, status))
        for e in errors:
            print("  ERROR:", e)
        for w in warnings:
            print("  WARNING:", w)
        if not errors and not warnings:
            print("  (schema OK, no issues found)")
        print()

        any_errors = any_errors or bool(errors)
        any_warnings = any_warnings or bool(warnings)

    if any_errors or (args.strict and any_warnings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

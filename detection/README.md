# Member 3 — Statistical Detection & Decision

Lightweight, non-machine-learning detector for the project
**Rate-Limiting and Threshold-Based DDoS Mitigation in SDN**.
It reads Member 2's per-second feature CSV and labels every window as
`normal`, `flash_crowd`, `naive_ddos`, `adaptive_ddos` (or `unknown` when the
input is unusable). It never blocks traffic or touches OpenFlow rules; that is
Member 4's job.

Standard library only. Tested with Python 3.14.2. See `HANDOFF.md` for the
Member 4 integration notes.

## Files

| File | Purpose |
|---|---|
| `config.py` | All settings (columns, thresholds, CUSUM, classifier, lag) |
| `loader.py` | Reads Member 2's CSV; empty/invalid cells become `None` and are reported |
| `thresholds.py` | Baseline from active normal windows; fixed-threshold check |
| `cusum.py` | One-sided CUSUM with a capped statistic |
| `detector.py` | Fusion + classification, one window at a time |
| `groundtruth.py` | Per-window true labels from Member 1's packet logs |
| `evaluate.py` | Threshold-only vs CUSUM-only vs combined, computed metrics |
| `live_detector.py` | Follows Member 2's CSV while it is written; writes decisions live |
| `replay_feed.py` | Pretends to be the monitor (replays a recorded CSV) for testing without Mininet |
| `run_threshold.py`, `run_compare.py`, `run_detector.py` | Step-by-step demos |
| `tests/` | 19 unit tests (loader, CUSUM, detector) |
| `data/decisions_<scenario>.csv` | Detector output for each scenario |

## Run (from this folder)

    python3 -m unittest discover -s tests
    python3 run_threshold.py
    python3 run_compare.py
    python3 run_detector.py
    python3 evaluate.py

The scripts expect Member 2's CSVs at `../sdn-ddos-monitoring/data/` and
Member 1's logs at `../sdn-ddos-monitoring/validation/`.

## Live mode (running as part of the pipeline)

Member 2's monitor appends one row per second to
`../sdn-ddos-monitoring/data/features.csv` and flushes after every row.
`live_detector.py` follows that file, runs the detector on each new row, and
appends the decision to `data/decisions_live.csv` (flushed per row), so
Member 4 can read decisions as they appear. Member 2's code is not modified;
the CSV is the interface.

    python3 live_detector.py                      # while the monitor runs

Options: `--input`, `--baseline` (a normal-run CSV, default
`features_normal.csv`), `--output`, `--poll`, `--idle-exit`.

It handles a half-written last line (waits for the rest) and a restarted
monitor (new file detected, detector state reset). Tested: replaying the
recorded adaptive run through `replay_feed.py` + `live_detector.py` produces
output identical to the offline `run_detector.py`.

Try it without Mininet, in two terminals:

    python3 live_detector.py --input data/replay_features.csv --idle-exit 5
    python3 replay_feed.py adaptive_ddos 0.2

## Input

Member 2's columns: `timestamp, PacketInRate, FlowCreationRate,
SourceIPEntropy, MeanIAT, Jitter, FlowTableOccupancy, ControllerRequestRate,
HalfOpenTCPRatio, DataPlanePacketRate`.

The loader raises an error if a column is missing, skips rows with a bad
timestamp, and sets empty, non-numeric, NaN, infinite or negative values to
`None`. Missing values are never filled in. `HalfOpenTCPRatio` is always empty
in the current data (UDP-only traffic) and is not used.

**Only `DataPlanePacketRate` drives decisions at the moment.** In the recorded
runs the Packet-In-based columns are almost always 0 after flow setup, because
the controller installs permanent flows, so they carry no usable signal.
`FlowTableOccupancy` is not used: it only reflects how many hosts have sent
traffic (5, 7 or 9) and never decreases.

## Method

### Baseline
`calibrate()` takes the median of `DataPlanePacketRate` over the **active**
windows (rate >= `ACTIVE_MIN_RATE` = 5) of a normal run. Idle windows are
mostly zeros and would make the median 0. Current baseline: 20 packets/s.
The baseline is fixed after calibration; it is not updated during detection,
so an attacker cannot raise it gradually. (Adaptive thresholding was therefore
not implemented.)

### A. Threshold
A window is high if `rate > 3 x baseline` (limit 60 packets/s).

### B. CUSUM (one-sided, upward)

    S_t = max(0, S_(t-1) + (x_t - mu - k))     alarm when S_t > h

- `x_t` rate in window t; `mu` baseline (20)
- `k = 5` slack: excess below `mu + k` adds nothing, so noise does not build up
- `h = 40` alarm level
- **Cap:** S is limited to `2 x h`. This is a change to plain CUSUM, added so
  the alarm clears within a few windows after an attack ends. Call it
  "CUSUM with a capped statistic".
- A missing value leaves S unchanged.

### C. Fusion score
`score = max(rate / limit, S / h)`. Both terms are divided by their own limit,
so they share a scale; score > 1 means abnormal. The decision itself uses the
rules below, not the score alone.

### D. Classification (uses only past windows)
1. **naive_ddos** — abnormal and the rate rose by >= `7 x baseline` (140
   packets/s) in a single window during the current sequence.
2. **adaptive_ddos** — at least two high-rate bursts separated by a pause of 3
   to 15 windows (`MIN_PAUSE`, `MAX_PAUSE`). The label is kept for 6 windows
   of silence (`HOLD_WINDOWS`) so a pause is not read as the attack ending.
   Gaps shorter than 3 windows count as a dip inside one burst.
3. **flash_crowd** — abnormal (threshold or CUSUM) but neither rule above:
   a gradual rise.
4. **normal** — otherwise. **unknown** — `DataPlanePacketRate` missing.

Burst counting uses the raw rate, not the CUSUM alarm, because CUSUM drains
slowly and would blur the pauses.

### Features not used
Source-IP entropy, inter-arrival time and jitter are 0 for almost every window
in the recorded runs (see Input), so entropy/IAT/jitter analysis is not part of
the decision. They can be added once the controller installs flows with idle
timeouts and the runs are re-recorded.

## Output

One row per window (`data/decisions_<scenario>.csv`, or the dict returned by
`Detector.process`):

    timestamp, traffic_class, score, reason, rule

`rule` is one of `none`, `threshold`, `cusum`, `onset_jump`, `repeat_burst`,
`hold`, `missing_input`. The schema is **proposed and not yet confirmed with
Member 4**.

## Results (computed from the labelled runs)

Ground truth: a window is "attack" between the first and last logged packet of
a naive/adaptive run (pauses inside an adaptive attack count as attack), shifted
by the measured 2-window lag. Pooled over the four recorded runs (502 windows).

**Task A — abnormal vs normal**

| Method | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| threshold | 62 | 0 | 16 | 424 | 1.000 | 0.795 | 0.886 | 0.000 |
| CUSUM | 66 | 4 | 12 | 420 | 0.943 | 0.846 | 0.892 | 0.009 |
| combined | 68 | 8 | 10 | 416 | 0.895 | 0.872 | 0.883 | 0.019 |

**Task B — attack vs legitimate (flash crowd counts as legitimate)**

| Method | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| threshold | 41 | 21 | 13 | 427 | 0.661 | 0.759 | 0.707 | 0.047 |
| CUSUM | 45 | 25 | 9 | 423 | 0.643 | 0.833 | 0.726 | 0.056 |
| combined | 38 | 7 | 16 | 441 | 0.844 | 0.704 | 0.768 | 0.016 |

**Detection latency (windows from first true attack window to first alarm)**

| Scenario | threshold | CUSUM | combined |
|---|---|---|---|
| naive_ddos | 1 | 1 | 1 |
| adaptive_ddos | 3 | 3 | 15 |

**Combined confusion matrix (rows truth, columns predicted)**

| Truth | normal | flash_crowd | naive_ddos | adaptive_ddos |
|---|---|---|---|---|
| normal | 416 | 1 | 1 | 6 |
| flash_crowd | 3 | 21 | 0 | 0 |
| naive_ddos | 1 | 0 | 20 | 0 |
| adaptive_ddos | 6 | 9 | 0 | 18 |

CUSUM vs threshold on a **synthetic** slow ramp (20 -> 80 packets/s over 60
windows, made-up input, see `run_compare.py`): CUSUM alarms at window 23, the
fixed threshold at window 50. The recorded runs contain no slow ramp.

## Known limitations

- **Results are in-sample.** Parameters (threshold factor 3, jump factor 7,
  pause range 3-15, hold 6) were chosen after inspecting these same four runs,
  with one run per scenario. Expect lower performance on new runs. No
  confidence intervals.
- **The first burst of an adaptive attack is labelled flash crowd.** The two
  look the same until the pause and second burst appear, so adaptive attacks
  are identified late (latency 15 windows vs 3 for threshold-only).
- **Threshold-only and CUSUM-only cannot separate a flash crowd from an
  attack**; they flag both. That is the reason for the combined detector
  (Task B precision 0.844 vs 0.661 / 0.643).
- **Hold windows create false positives** after an adaptive attack ends
  (6 normal windows labelled adaptive).
- **Ramp-up windows at low rate** (below the 60 packets/s limit) cannot be
  flagged by any rate-based method; this caps recall.
- **Flash crowd vs adaptive depends on the pause rule.** A genuine flash crowd
  that dips and recovers for 3+ windows would be mislabelled adaptive.
- **Single feature.** Decisions depend on `DataPlanePacketRate`; if Member 2
  changes how it is measured, thresholds must be recalibrated.
- **2-window lag.** A feature row describes traffic from 2 windows earlier
  (measured; correlation peaks at lag 2 in all four runs).

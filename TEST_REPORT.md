# Test Report

Project: Rate-Limiting and Threshold-Based DDoS Mitigation in SDN.
Date: 2026-10-23. Machine: Ubuntu (kernel 7.0), Python 3.14.4, Mininet 2.3.0,
Open vSwitch 3.7.1, os-ken 4.2.2 (`~/ryu-venv`); frontend checks in the
built-in browser pane of the Claude desktop app (Chromium-based).

Every result below was produced by actually running the command shown.
"Synthetic" marks tests that use hand-made inputs or a mock; they are labelled
as such in the test files too.

## 1. Automated checks (no root) — `bash run_tests.sh`

Final run after the last code change: **10 / 10 PASS** (output saved in
`member4_mitigation/logs/run_tests_final.out`, gitignored).

| # | Check | Command (inside `run_tests.sh`) | Result |
|---|---|---|---|
| 1 | M1 log validator on recorded logs | `python3 trafficgen/validate_log.py sdn-ddos-monitoring/validation/*/h2.csv` | PASS (normal, naive: PASS; flash crowd, adaptive: WARN = harmless 0.1 ms thread interleaving) |
| 2 | M1 scripts syntax | `ast.parse` of 9 generator/topology files | PASS (9 files) |
| 3 | M2 unit tests | `cd sdn-ddos-monitoring && python3 -m unittest discover -s tests` | PASS, 12 tests |
| 4 | M2 feature CSV format | `python3 tests/check_csv_format.py` | PASS, 4 files |
| 5 | M2 features vs M1 ground truth | `python3 tests/compare_ground_truth.py naive_ddos` | PASS (7002 vs 6988 packets) |
| 6 | M3 unit tests | `cd detection && python3 -m unittest discover -s tests` | PASS, 19 tests |
| 7 | M3 evaluation reproduces its README | `python3 evaluate.py` | PASS (identical tables) |
| 8 | M4 unit / API / integration tests | `python3 -m unittest discover -s member4_mitigation/tests -t .` | PASS, 56 tests (53 run, 3 skipped here because they need os-ken; see #9) |
| 9 | M4 OpenFlow message serialization | `~/ryu-venv/bin/python -m unittest member4_mitigation.tests.test_flow_rules_osken` | PASS, 3 tests |
| 10 | Controller apps import under os-ken | `import controller.simple_switch_13, monitor, member4_mitigation.mitigation_app` | PASS |

### Member 4 test files

| File | Tests | What it covers | Mocks / synthetic |
|---|---|---|---|
| `test_decisions.py` | 7 | decision parsing/validation, class mapping, LF/CRLF files, Member 3's recorded files | recorded files are real; small inline rows synthetic |
| `test_follower.py` | 6 | live decision file: missing file, skip stale rows, half-written line, truncation/restart, bad row not fatal | synthetic files |
| `test_mitigation.py` | 8 | policy: normal and flash crowd never mitigated, naive start/stop, hold keeps on, unknown keeps state, release delay | synthetic decisions |
| `test_rate_limiter.py` | 8 | offender selection: rates, counter reset, normal host never selected, pausing attacker kept, protected ports, cap, per-switch state, disconnect | synthetic counters |
| `test_tools.py` | 5 | sink counting, threshold/CUSUM baselines, missing values, resource monitor on a real child process | synthetic |
| `test_evaluator.py` | 6 | every metric against known answers, early release flagged (not negative), compare tables | **synthetic run folder** |
| `test_dashboard_state.py` | 4 | snapshot contents, never writes, corrupt/missing files don't crash, run-id confinement | synthetic run folder |
| `test_dashboard_api.py` | 9 | real HTTP server: page, health, state, summary, 404, bad Host, cross-site POST refused, read-only POST refused, validation (400), conflict (409), start/stop | **mock runner** (stands in for `run_experiment.py`, which needs root) |
| `test_flow_rules_osken.py` | 3 | meter/flow/delete/barrier/port-stats messages build and serialize | fake datapath object (no switch) |

## 2. Testbed checks (root) — `bash member4_mitigation/verify_testbed.sh`

Run once, output in `member4_mitigation/logs/verify_testbed.out`:

| Step | Result |
|---|---|
| OpenFlow 1.3 meter support (throw-away bridge) | PASS — `max_meter:200000 max_bands:1`, `band_types: drop`, meter readable after add |
| Controller (switch + monitor + mitigation app) starts | PASS — listening on 6653 |
| Member 1 `topo/test_pingall.py` | PASS — `pingall drop percentage: 0.0%` |
| Member 4 app sees the switch | PASS |
| Cleanup | PASS (controller stopped, `mn -c`) — **ALL TESTBED CHECKS PASSED** |

## 3. End-to-end experiments (root) — `run_experiment.py`

34 run folders in `member4_mitigation/results/`: **33 finished**, 1 aborted
(intentionally stopped to test the Stop button). Finished runs by configuration:

| Detector + mitigation | Runs | Traffic setups |
|---|---|---|
| combined + on (proposed) | 9 | normal, flash crowd, naive ×3, adaptive subtle, moderate ×2, aggressive |
| combined + off (no mitigation) | 6 | all six |
| threshold-only + on | 6 | all six |
| CUSUM-only + on | 6 | all six |
| entropy-only + on | 6 | all six |

How they were started: 24 by `run_all.sh` (tag `r1`), 1 from the terminal
(first test), 1 while testing the dashboard live (`livedemo`), 8 from the
dashboard's control API/UI (`ui`, including the 6 entropy-only runs and the
stopped run). Every finished run has `metrics.json`; comparison tables are
`results/summary.md` and `results/offline_detection.md`.

Verified per run (from its own files): all OpenFlow errors = 0; meters were
confirmed by Barrier on the switch (`limit_confirmed`); in the 7 runs with the
switch-side sampler, the switch's own flow/meter count equalled the app's
limits and was 0 at the end; no legitimate host was limited in any attack run.

Detector replay determinism: replaying Member 3's combined detector over each
run's recorded features reproduced the live decisions in **15 of 15** runs.

## 4. Frontend (browser) checks

Performed in the desktop app's browser pane against the running server.

| Check | Result |
|---|---|
| Server starts read-only (`server.py`) and in control mode (`sudo … --control`) | PASS |
| Page loads, no console messages on a clean load (Live and Results views) | PASS |
| Health pill: "server OK · read-only / control mode"; "server unreachable" while the server was restarting, page recovered by itself | PASS |
| Read-only mode: controls disabled with explanation; POST refused (403) | PASS (browser + API test) |
| **Start** from the UI (naive DDoS): run started, LIVE status, decision tile "Naive DDoS", mitigation ON, h2–h5 limited, run finished exit 0 | PASS |
| **Stop** from the UI during a normal run: runner cleaned up (no leftover processes, port 6653 free, no Mininet links), run marked aborted/"stopped" | PASS |
| **Clean up Mininet** button | PASS ("Mininet cleanup finished.") |
| Run picker: follow newest; replay recorded run | PASS |
| Charts: values, shading, reference lines, crosshair tooltip (survives the 1 s redraw), y-axis ticks, gap filling during pauses | PASS (after fixes listed below) |
| Results view numbers equal `metrics.json` / `offline_detection.md` (spot-checked flash-crowd PDRs and all detector rows) | PASS |
| Light and dark mode; phone width 375 px (no horizontal scroll); tablet | PASS |
| Killing the read-only dashboard (`kill -9`) during an attack does not affect the experiment | PASS (run finished, meters released, 0 errors) |

## 5. Problems found by testing and fixed

| Problem | Fix |
|---|---|
| Dashboard tooltip vanished every second (chart redraw) | pointer position kept across redraws |
| Victim chart drew straight lines across adaptive pauses (no sink rows = 0 packets) | missing seconds filled with 0 |
| Decision strip overflowed phone screens; long run names overflowed picker | flexible cells; picker width rules |
| `release_delay_s` negative when mitigation was lifted before the attack ended | redefined (first removal after attack end) + `released_before_attack_end` flag; all runs re-evaluated |
| Strict decision validator rejected the new `entropy` rule | rule added to the interface list |
| Stopped runs printed a raw `KeyboardInterrupt` traceback | clear "stopped by user" message, exit 130 |
| Aborted runs would have entered the detection comparison | excluded (only `finished` runs) |
| Root-run generators left a root-owned `trafficgen/__pycache__` (compile check failed) | `PYTHONDONTWRITEBYTECODE` for root processes; compile check writes nothing |
| PDF generator: tables/code/`--flags` rendered wrongly | renderer rewritten, output inspected page by page |

## 6. Not tested / blocked

| Item | Status |
|---|---|
| Repeated runs per configuration (confidence intervals) | not done — most configurations have 1 run; `REPEATS=3 bash member4_mitigation/run_all.sh` (~2.5 h) |
| Live flash-crowd and adaptive runs started from the UI button | only via the same control API from a script (entropy batch); the UI button itself was exercised with naive and normal |
| Browsers other than the desktop app's built-in (Chromium-based) pane | not tested |
| Multi-switch topologies, real hardware switches | out of scope (single-switch testbed) |
| Controller-side FlowMod throttling | not implemented (design decision, see README) |

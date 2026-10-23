# Completion Checklist

Status as of 2026-10-23. PASS = implemented and verified by a test or a
recorded run (evidence in `TEST_REPORT.md`); PARTIAL = works with a stated
limitation; NOT DONE / BLOCKED = explained.

## Member 1 — traffic and attack generation

| Requirement | Status | Evidence / note |
|---|---|---|
| Normal, genuine flash crowd, naive low-rate DDoS, adaptive flash-crowd-mimicking DDoS | PASS | `trafficgen/*.py`; all four run in recorded experiments |
| Subtle / moderate / aggressive adaptive levels | PASS | presets in `adaptive_ddos_traffic.py`; each level run 5–6 times (now including subtle and aggressive) |
| Repeatable, configurable, ground-truth labels | PASS | CLI parameters; per-packet send logs + JSON sidecar; `run_experiment.py` fixes the settings |
| Isolated Mininet testbed | PASS | `topo/basic_topo.py`, `test_pingall.py` 0 % loss |

## Member 2 — monitoring and feature extraction

| Requirement | Status | Evidence / note |
|---|---|---|
| Switch/controller statistics, 1-s windows, consistent timestamps | PASS | `monitor.py`; 12 unit tests; format check |
| Features required by detection | PASS | `DataPlanePacketRate` matches Member 1's send logs within 0.5 % |
| Missing / invalid values handled | PASS | Member 3's loader sets them to None; Member 4 follower skips bad rows (tests) |
| Packet-In features informative | PARTIAL | ~0 after flow setup because Member 1's controller installs permanent flows (documented team decision) |

## Member 3 — statistical detection

| Requirement | Status | Evidence / note |
|---|---|---|
| CUSUM, threshold, temporal (burst–pause) fusion | PASS | `detection/`, 19 unit tests |
| Four classes + unknown; timestamp, class, score, reason | PASS | `decisions.csv` schema, validated by Member 4 |
| Entropy analysis | PARTIAL | implemented as entropy-only baseline and measured (recall 0.007); not used in the fused decision because the feature is ~0 |
| Jitter analysis | NOT DONE | jitter feature is ~0 for the same reason; documented limitation |
| Baselines: entropy-only, CUSUM-only, threshold-only vs combined | PASS | live runs (6 each) + replay on identical features (`offline_detection.md`) |
| Real calculated values only | PASS | replay reproduces live decisions 15/15 |

## Member 4 — mitigation and evaluation

| Requirement | Status | Evidence / note |
|---|---|---|
| Policy driven by Member 3's actual decisions | PASS | `mitigation.py`, 8 tests; live runs |
| Normal traffic not touched | PASS | 0 limits in all normal runs (proposed); tests |
| No blanket blocking of flash crowds | PASS | proposed: 0 hosts limited, legit PDR 1.000 |
| Targeted rate limiting of attackers | PASS | meters on exactly the attack ports; 0 legitimate hosts limited in any attack run |
| Supported mechanisms verified on this OVS | PASS | `verify_testbed.sh`; switch-side `ovs.csv` |
| Packet-In reduction / flow-table protection | PARTIAL | limited ports bypass table-miss; ≤ 1 flow + 1 meter per port; Packet-In already ~0 with permanent flows |
| Controller-side FlowMod throttling | NOT DONE | would require changing Member 1's controller; documented |
| Rule install, removal, recovery | PASS | Barrier-confirmed install/remove in every run; stale-rule cleanup confirmed at every switch connect in mitigation-on runs (`cleanup_confirmed`; monitor-only runs never touch the switch); detector-restart reset tested; switch shows 0 rules after each run |
| Switch disconnection mid-run | PARTIAL | state is dropped on disconnect and rules re-installed on the next decision (code); not exercised by a test |
| Logging of decisions, actions, rules, errors, response times | PASS | `actions.csv`, `events.csv` |
| Detection, network, mitigation, resource metrics with units | PASS | `evaluator.py`, README metric table; tested on known fixture |
| Detection kept separate from mitigation | PASS | Results A (detection replay) vs B–D (mitigation) |
| Configurable without editing code | PASS | `M4_*` / `--set`, `m4.env.example` |

## Frontend and integration

| Requirement | Status | Evidence / note |
|---|---|---|
| Frontend starts; backend starts; frontend reaches backend | PASS | browser checks, API tests |
| Every control functional (Start, Stop, Cleanup, run picker, tabs) | PASS | exercised in the browser against the real testbed |
| Live data, not demo values; recorded vs live clearly labelled | PASS | all values from run files; "LIVE" vs finished/stopped; Results note says "real measurements" |
| Loading / empty / error states; failed requests don't crash | PASS | server-down test, read-only mode, empty results, corrupt files (tests) |
| Displayed decision and mitigation status match backend | PASS | UI tile values compared with `events.csv` / API during a live run |
| UI numbers match recorded data | PASS | spot-checked against `metrics.json` / `offline_detection.md` |
| Restart without corrupting state | PASS | dashboard restarted several times; killed mid-run without effect |

## Documentation and deliverables

| Deliverable | Status |
|---|---|
| `README.md` (root) | PASS |
| `FRONTEND_EXPLANATION_AND_DEMO_GUIDE.md` + `.pdf` | PASS (PDF built with `docs/make_pdf.py`, 8 pages, inspected) |
| `TEST_REPORT.md` | PASS |
| `COMPLETION_CHECKLIST.md` | PASS (this file) |
| Architecture diagram `docs/ARCHITECTURE.md` | PASS |
| Phase 1 audit `docs/PROJECT_AUDIT.md` | PASS |
| Environment example (no secrets) `member4_mitigation/m4.env.example` | PASS |
| Sample fixtures labelled | PASS (synthetic fixtures labelled in each test file; recorded data listed in README) |
| Actual experiment outputs | PASS (`member4_mitigation/results/`, 33 finished runs) |

## Open items

| Item | Status |
|---|---|
| Repeat runs for averages / confidence intervals | NOT DONE (`REPEATS=3 bash member4_mitigation/run_all.sh`, ~2.5 h) |
| Member 3 to confirm the interface choices (hold keeps mitigation, unknown keeps state, no flash-crowd cap) | team action |
| Commit the work to Git | not done — awaiting the owner's instruction |

# Project audit (Phase 1)

Repository state inspected before the final integration pass. "Before" =
state of `main` at commit `c1f06b6` (Members 1–3 merged, no Member 4);
"After" = this working tree.

## Stack (actual)

| Item | What the project uses |
|---|---|
| SDN controller | os-ken 4.2.2 (maintained Ryu fork) in `~/ryu-venv`, started with `tools/osken_run.py` (the PyPI wheel has no `osken-manager`) |
| OpenFlow | 1.3 |
| Switch / emulator | Open vSwitch 3.7.1, Mininet 2.3.0, topology `topo/basic_topo.py` (1 switch, h1–h6) |
| Language | Python 3.14 (system + venv); standard library only except os-ken and psutil |
| Frontend | single page `member4_mitigation/dashboard/index.html`: HTML + CSS + plain JavaScript, hand-written SVG charts, no framework, no build step, no external libraries |
| Backend API | `member4_mitigation/dashboard/server.py`: Python `http.server` (stdlib), JSON endpoints |
| Database | none — every module exchanges CSV/JSON files |

## Members 1–3 at the start

| Member | Status found | Issues found |
|---|---|---|
| 1 Traffic generation | complete: 4 scenarios, adaptive presets subtle/moderate/aggressive, feint/pause, log validator, interface doc | docstring referred to a missing `run_adaptive.sh`; only `moderate` adaptive was ever recorded |
| 2 Monitoring | complete: os-ken app, 1-s feature windows, unit tests, validation vs Member 1 logs | README and `tests/check_scenario.sh` hard-coded `~/member1_traffic`, `~/member2_monitoring` (wrong in this repo) |
| 3 Detection | complete: threshold, capped CUSUM, fusion classifier (4 classes + unknown), live follower, evaluation | entropy / jitter / IAT not used because Packet-In features are flat (permanent flows); no entropy-only baseline; interface questions for Member 4 open |
| 4 Mitigation & evaluation | absent | — |

Shared design facts that drive Member 4:
- Member 1's controller installs **permanent** flows, so after flow setup almost no Packet-Ins reach the controller; Packet-In-based features (entropy, IAT, jitter) are ~0 and only `DataPlanePacketRate` carries the traffic signal.
- Member 3's decisions are **network-wide** (no source field) — attribution of offenders must come from elsewhere.

## Frontend controls (before → after)

| Control / section | Before | After |
|---|---|---|
| Any frontend | none existed | dashboard with Live run and Results views |
| Start / Stop / Cleanup experiment | — | functional in `--control` mode (`POST /api/control/*`), disabled with an explanation in read-only mode |
| Run picker | — | `GET /api/runs`; follows newest run or replays a recorded one |
| Status tiles, charts, decision strip, events, resources | — | `GET /api/state` from the run's real files |
| Results charts and tables | — | `GET /api/summary` from `metrics.json` + `offline_detection.csv` |
| Server health pill | — | `GET /api/health` |

No placeholder widgets, mock data or hard-coded demo values are used in the page.

## Fixed / completed in this pass

- Member 1: stale `run_adaptive.sh` reference replaced (points to the Member 4 runner, which automates synchronized multi-host adaptive runs).
- Member 2: README and `check_scenario.sh` paths made repository-relative.
- Member 3 (scope respected, nothing rewritten): entropy-only baseline added as a Member 4 baseline that reuses Member 3's loop; `.gitignore` for live outputs.
- Member 4: implemented in full (`member4_mitigation/`), see its README.

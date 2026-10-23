# Rate-Limiting and Threshold-Based DDoS Mitigation in SDN

A lightweight, **non-machine-learning** framework that detects and mitigates
DDoS attacks in a Software Defined Network, with a focus on **adaptive
low-rate attacks that imitate genuine flash crowds**. Four modules, one per
team member, run on a Mininet + Open vSwitch testbed controlled by an
OpenFlow 1.3 controller (os-ken, the maintained fork of Ryu), plus a web
dashboard for live demonstration.

| Member | Module | Folder | Own docs |
|---|---|---|---|
| 1 | Traffic and attack generation (normal, flash crowd, naive DDoS, adaptive DDoS subtle/moderate/aggressive) | `trafficgen/`, `topo/`, `controller/`, `tools/` | `docs/MEMBER1_INTERFACE.md` |
| 2 | Monitoring and feature extraction (1-s feature windows from OpenFlow) | `sdn-ddos-monitoring/` | `sdn-ddos-monitoring/README.md`, `docs/METHODOLOGY.md` |
| 3 | Statistical detection (threshold, capped CUSUM, temporal burst/pause fusion) | `detection/` | `detection/README.md`, `detection/HANDOFF.md` |
| 4 | Mitigation (OpenFlow meters), evaluation, baselines, dashboard | `member4_mitigation/` | `member4_mitigation/README.md` |

Further documents: `docs/ARCHITECTURE.md` (diagram and interfaces),
`FRONTEND_EXPLANATION_AND_DEMO_GUIDE.md` (+ `.pdf`) (teacher demo),
`TEST_REPORT.md`, `COMPLETION_CHECKLIST.md`, `docs/PROJECT_AUDIT.md`.

## Architecture in one paragraph

Member 1's generators send UDP traffic from Mininet hosts h2–h6 to the victim
h1 through one OVS switch. A single os-ken controller process runs Member 1's
learning switch, Member 2's monitor (writes one feature row per second) and
Member 4's mitigation app. Member 3's detector (separate process) follows the
feature file and writes one decision per second (`normal`, `flash_crowd`,
`naive_ddos`, `adaptive_ddos`, `unknown`). Member 4's app follows the
decisions; on an attack it finds the sending hosts from switch port counters
and installs an OpenFlow **meter** (drop above 10 pkt/s) for each, and removes
them when the attack ends. Everything is logged to CSV; an evaluator computes
the metrics and the dashboard (`http://127.0.0.1:8050/`) shows it live.
Diagram: `docs/ARCHITECTURE.md`.

## Prerequisites (as used and tested)

| Software | Version | Install |
|---|---|---|
| Ubuntu | with kernel OVS datapath (meters supported) | — |
| Mininet | 2.3.0 | `sudo apt install mininet` |
| Open vSwitch | 3.7.1 | `sudo apt install openvswitch-switch` |
| Python | 3.14 (system) | — |
| psutil | system package | `sudo apt install python3-psutil` |
| os-ken | 4.2.2 in `~/ryu-venv` | `python3 -m venv ~/ryu-venv && ~/ryu-venv/bin/pip install os-ken==4.2.2 eventlet==0.41.2` |

No database, no Node.js and no build step: the dashboard is one HTML file
served by Python's standard library.

## Configuration

All mitigation settings live in `member4_mitigation/config.py` and can be
overridden without editing code (`M4_<NAME>` environment variables, or
`--set NAME=VALUE` on `run_experiment.py`); see
`member4_mitigation/m4.env.example`. Detector settings: `detection/config.py`.
Monitoring settings: `sdn-ddos-monitoring/config.py`. The project uses no
secrets or credentials.

## Running

All commands from the repository root. Only one controller may use port 6653;
check with `ss -ltnp | grep 6653`.

**Automated checks (no root):**

    bash run_tests.sh

**Testbed smoke test (meters, controller, Mininet pingall):**

    bash member4_mitigation/verify_testbed.sh

**One complete experiment** (~1.5–2 min; controller, detector, Mininet,
traffic, measurement and evaluation are all started and stopped for you;
results in `member4_mitigation/results/<time>_<scenario>_.../`):

    sudo python3 member4_mitigation/run_experiment.py --scenario normal
    sudo python3 member4_mitigation/run_experiment.py --scenario flash_crowd
    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos
    sudo python3 member4_mitigation/run_experiment.py --scenario adaptive_ddos --level subtle|moderate|aggressive

Options: `--detector combined|threshold|cusum|entropy`, `--mitigation on|off`,
`--set NAME=VALUE`, `--tag TEXT`.

**Baseline comparison (full matrix, ~50 min, then tables):**

    bash member4_mitigation/run_all.sh
    python3 -m member4_mitigation.compare             # member4_mitigation/results/summary.md
    python3 -m member4_mitigation.offline_detection   # member4_mitigation/results/offline_detection.md

**Dashboard (frontend):**

    python3 member4_mitigation/dashboard/server.py              # read-only, no root
    sudo python3 member4_mitigation/dashboard/server.py --control   # adds Start/Stop buttons

then open **http://127.0.0.1:8050/**. The Live view follows the newest run; the
Results view shows the comparison of all recorded runs.

**Manual session (Members 1–3's original workflow, now with mitigation):**

    PYTHONPATH=$PWD:$PWD/sdn-ddos-monitoring ~/ryu-venv/bin/python tools/osken_run.py \
        controller.simple_switch_13 monitor member4_mitigation.mitigation_app     # terminal A
    cd detection && python3 live_detector.py                                       # terminal B
    sudo python3 topo/basic_topo.py                                                # terminal C

## Where results are stored

| Path | Content | Real or sample |
|---|---|---|
| `member4_mitigation/results/<run>/` | everything one experiment produced (see `docs/ARCHITECTURE.md`) | real testbed measurements |
| `member4_mitigation/results/summary.{md,csv}` | per-configuration comparison (live runs) | computed from real runs |
| `member4_mitigation/results/offline_detection.{md,csv}` | four detectors on identical recorded features | computed from real runs |
| `sdn-ddos-monitoring/validation/`, `sdn-ddos-monitoring/data/features_*.csv`, `detection/data/decisions_*.csv` | Members 1–3's recorded reference runs | real (recorded by Members 1–3) |
| `member4_mitigation/tests/*` fixtures | hand-made inputs with known answers | **synthetic**, labelled in each test file |
| `member4_mitigation/logs/` | manual-session logs, UI runner output (gitignored) | real, transient |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `AttributeError: 'HubThread' object has no attribute 'kill'` when the controller exits | os-ken's normal shutdown message; if it appears immediately at start, port 6653 is in use (`ss -ltnp \| grep 6653`) |
| `port 6653 is already in use` from `run_experiment.py` | stop the other controller (Ctrl+C in its terminal, or `kill <pid>`) |
| Mininet errors about existing interfaces / `s1` | `sudo mn -c` (or the dashboard's "Clean up Mininet" button in control mode) |
| Dashboard shows "server unreachable" | start `python3 member4_mitigation/dashboard/server.py`; page recovers by itself |
| Dashboard Start button disabled | server is read-only; restart it with `sudo … server.py --control` |
| `Address already in use` for the dashboard | another dashboard runs on 8050: stop it or use `--port 8051` |
| `Permission denied …/__pycache__/…` | a cache folder created by root earlier: `sudo rm -rf trafficgen/__pycache__` |
| `No module named 'os_ken'` | use `~/ryu-venv/bin/python` for the controller (the runner does this) |

## Known limitations

- Detection relies on one feature (`DataPlanePacketRate`): Member 1's controller
  installs permanent flows, so Packet-In-based features (entropy, IAT, jitter)
  are ~0 after flow setup. The entropy-only baseline confirms this (recall ≈ 0).
- Adaptive attacks are recognised only at their second burst; the subtle level
  is largely not detected (it stays under the rate limits) — this is the
  evasion the project studies.
- Offenders are identified by sending rate per switch port (one host per port,
  no spoofing). Controller-side FlowMod throttling is not implemented.
- Results come from one machine, one switch, six hosts and few repeats per
  configuration; Member 3's thresholds were tuned on recorded runs. No
  comparison with published ML systems is claimed.

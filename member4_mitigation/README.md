# Member 4 — Mitigation and Performance Evaluation

Part of **Rate-Limiting and Threshold-Based DDoS Mitigation in SDN**.
This module turns Member 3's per-window decisions into OpenFlow mitigation,
and measures detection, mitigation, network and resource performance of the
integrated system. It does not change how Members 1–3 generate traffic,
extract features or classify windows.

## Files

| File | Purpose |
|---|---|
| `config.py` | All settings; each can be overridden per run with `M4_<NAME>` (or `--set NAME=VALUE`) |
| `decisions.py` | Reads/validates Member 3's decisions; `DecisionFollower` reads the live file |
| `mitigation.py` | Policy: decision → `start` / `keep` / `stop` / `none` |
| `rate_limiter.py` | Picks offending switch ports from per-port packet rates |
| `flow_rules.py` | OpenFlow 1.3 messages: meter + flow install, removal, barrier, port stats |
| `mitigation_app.py` | os-ken app tying it together inside the controller |
| `baseline_detectors.py` | Live threshold-only / CUSUM-only / entropy-only detectors (Member 3's parts) |
| `offline_detection.py` | All four detectors replayed on the SAME recorded features → `results/offline_detection.*` |
| `sink.py` | Victim-side UDP sink that counts received packets per second and source |
| `resource_monitor.py` | CPU / memory sampling of the controller and detector |
| `run_experiment.py` | Runs one complete labelled experiment (needs sudo); also samples the switch's own flow/meter counters (`ovs.csv`) |
| `verify_testbed.sh` | Smoke test: OVS meter support + controller + Member 1's pingall |
| `m4.env.example` | All settings with defaults, as `M4_*` overrides (no secrets) |
| `run_all.sh` | Runs the whole experiment matrix, then `compare.py` |
| `evaluator.py` | Metrics of one run → `metrics.json` |
| `compare.py` | All runs → `results/summary.csv`, `results/summary.md` |
| `dashboard/` | Dashboard: `server.py` (API), `state.py` (read-only snapshots), `control.py` (start/stop, `--control` only), `index.html` |
| `tests/` | unit, API and integration tests (see TEST_REPORT.md at the repository root) |
| `results/` | Experiment outputs, one folder per run |

## Requirements

Ubuntu, Mininet 2.3.0, Open vSwitch 3.7.1 (OpenFlow 1.3, meters supported —
checked with `ovs-ofctl meter-features`: `max_meter:200000`, band type `drop`),
system Python 3 with `python3-psutil`, and os-ken 4.2.2 in `~/ryu-venv`
(see `requirements.txt`).

## Interface with Member 3

Input: `timestamp,traffic_class,score,reason,rule`, one row per 1-s window,
read by column name (extra columns allowed). Classes: `normal`,
`flash_crowd`, `naive_ddos`, `adaptive_ddos`, `unknown`.

Working agreements (configurable, to be confirmed by Member 3):

| Topic | Choice | Setting |
|---|---|---|
| Which classes trigger mitigation | `naive_ddos`, `adaptive_ddos` | `MITIGATE_CLASSES` |
| `hold` rows (pauses of an adaptive attack) | keep mitigation on | `KEEP_DURING_HOLD` |
| `unknown` rows | log, keep current state | `UNKNOWN_KEEPS_STATE` |
| `score` | logged only; it is a ratio to a limit, not a confidence | — |

## How to run

Unit tests (no root):

    python3 -m unittest discover -s member4_mitigation/tests -t .
    ~/ryu-venv/bin/python -m unittest member4_mitigation.tests.test_flow_rules_osken

One experiment (~90–100 s; stop any other controller on port 6653 first):

    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos
    sudo python3 member4_mitigation/run_experiment.py --scenario adaptive_ddos --level subtle
    sudo python3 member4_mitigation/run_experiment.py --scenario flash_crowd --mitigation off
    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos --detector threshold
    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos --set METER_RATE_PPS=5

Full matrix and comparison:

    bash member4_mitigation/run_all.sh            # 30 runs (6 traffic setups x 5 configurations)
    CONFIGS="entropy:on" bash member4_mitigation/run_all.sh   # a subset
    python3 -m member4_mitigation.compare         # rebuild summary only
    python3 -m member4_mitigation.offline_detection   # detectors on identical recorded features

Testbed smoke test (meters, controller, pingall):

    bash member4_mitigation/verify_testbed.sh

Manual use inside your own Mininet session: add `member4_mitigation.mitigation_app`
to the controller command and run Member 3's `live_detector.py`:

    PYTHONPATH=$PWD:$PWD/sdn-ddos-monitoring ~/ryu-venv/bin/python tools/osken_run.py \
        controller.simple_switch_13 monitor member4_mitigation.mitigation_app

## Live demo dashboard

A web page that shows a run as it happens: the detector's current class,
whether mitigation is on, which hosts are limited, per-host packet rates
into the switch and delivered to the victim, the per-window decision strip,
mitigation events and controller CPU/memory. Past runs can be replayed in full.

    python3 member4_mitigation/dashboard/server.py        # then open http://127.0.0.1:8050/
    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos   # another terminal

It cannot disturb the experiment: it is a separate process using only the
Python standard library, it only READS the files the run already writes
(never writes, never contacts the controller or switch), it listens on
localhost only, and every read error becomes a warning on the page instead
of a crash. Starting, stopping or killing it at any time has no effect on
the controller, detector or Mininet (tested with `kill -9` mid-attack). It
follows the newest run folder automatically; `--run-dir member4_mitigation/logs`
shows a manual session. The **Results** view shows the comparison tables and
charts from all recorded runs.

Optional control mode adds Start / Stop / Clean-up buttons:

    sudo python3 member4_mitigation/dashboard/server.py --control

It launches the existing `run_experiment.py` with arguments chosen from fixed
lists (one run at a time, in its own process session, so stopping the server
never stops an experiment); Stop sends Ctrl+C to the runner so its normal
cleanup runs. POST requests are accepted only from the page itself
(`X-M4-Request` header, Host/Origin checks). Full API list: `dashboard/server.py`.

## Methodology

### Mitigation

1. **Decision → policy.** Every new decision row is fed, in time order, to a
   two-state policy (off/on). An attack class switches it on; it switches off
   after `RELEASE_AFTER_CLEAN_WINDOWS` (default 1) consecutive non-attack
   windows. Member 3's `hold` rows keep it on during adaptive pauses;
   `flash_crowd` never switches it on, so legitimate surges are not penalised.
2. **Attribution.** Member 3's decision is network-wide (no source field).
   The app polls OpenFlow port statistics every second; the received-packet
   rate of a switch port is the sending rate of the host on that port. While
   mitigation is on, a port is an offender if its rate reached
   `OFFENDER_MIN_PPS` (20 pkt/s = 2 × the normal per-host rate) at least once
   in the last `OFFENDER_LOOKBACK_S` (10 s), so a pausing attacker stays
   selected. At most `MAX_LIMITED_PORTS` ports are limited; `PROTECTED_PORTS`
   never are.
3. **Enforcement (data plane).** Per offender port P: an OpenFlow meter with
   one drop band at `METER_RATE_PPS` (10 pkt/s = normal per-host rate) and a
   flow `in_port=P → meter P → output:NORMAL` at priority 100 (above Member 1's
   learned flows, priority 1), tagged with cookie `0x4D34`. Offenders are
   reduced to a normal client's rate rather than blocked, so a misattributed
   legitimate host keeps working. A Barrier after each batch timestamps when
   the switch has applied the rules.
4. **Release and recovery.** On `stop`, all flows with our cookie and all
   meters are deleted. On every switch (re)connection, leftovers are deleted
   first. A detector restart (decision file truncated/replaced) resets the
   policy and removes all rules.

The four objectives are distinct and handled as follows:

| Objective | What this module does |
|---|---|
| Limit data-plane traffic | Per-offender meters (drop above `METER_RATE_PPS`) |
| Reduce Packet-In reaching the controller | An offender's packets match our rule, not the table-miss rule, so they cause no Packet-In while limited. With Member 1's permanent flows, Packet-Ins are already near zero after setup (measured as `packet_in_total`) |
| Limit flow-table growth | We add at most 1 flow + 1 meter per limited port (bounded by `MAX_LIMITED_PORTS`); occupancy is measured (`flow_table_max_entries`). The attacks do not spoof addresses, so they do not grow Member 1's table beyond one entry per host pair |
| Limit controller-side flow installation | Not implemented: it would require changing Member 1's controller (`add_flow`). Not needed by the measured FlowMod load; listed under limitations |

Note on detection during mitigation: OVS counts a packet on a flow and on a
port before the meter drops it, so Member 2's `DataPlanePacketRate` and our
port rates keep showing the attack while it is limited. Mitigation therefore
does not hide the attack from the detector and release it early.

### Experiments

`run_experiment.py` uses the topology of `topo/basic_topo.py` (1 OVS switch,
h1 = victim, h2–h6) and Member 1's generators with the settings of the
recorded runs:

| Scenario | Hosts | Generator settings |
|---|---|---|
| normal | h2, h3 | `normal_traffic.py --rate=10 --duration=30` |
| flash_crowd | h2, h3, h4 | `flash_crowd_traffic.py --num-flows=5 --ramp-up=10 --hold=12 --rate-min=5 --rate-max=15` |
| naive_ddos | h2–h5 | `naive_ddos_traffic.py --rate=100 --duration=20` |
| adaptive_ddos | h2–h5 | `adaptive_ddos_traffic.py --duration=40 --attack-level={subtle,moderate,aggressive}`, shared `--start-at` |

Timeline per run: controller + detector start; switch connects; 10 s warm-up;
measuring sink on h1, a **legitimate background client on h6** (10 pkt/s for
the whole run) and `ping -i 0.5` h6→h1 start; after 15 s the scenario
traffic starts; 25 s after it ends everything stops. h6 is always
legitimate; in normal/flash-crowd runs the scenario hosts are legitimate too.

Configurations (`run_all.sh`), same traffic for each:

| Name | Detector | Mitigation |
|---|---|---|
| Proposed | Member 3 combined | on |
| No-mitigation baseline | Member 3 combined | off (policy logged, no rules) |
| Threshold-only baseline | rate > 3 × baseline | on |
| CUSUM-only baseline | capped CUSUM | on |
| Entropy-only baseline | SourceIPEntropy > max(mean + 3σ, 1 bit) of the normal run | on |

In addition, `offline_detection.py` replays all four detectors over the SAME
recorded feature windows of every run (identical input, so differences come
from the decision logic only); its replay of the combined detector reproduces
the live decisions exactly, which is checked and reported.

The baseline detectors reuse Member 3's baseline, limits, CUSUM and live loop;
only the classifier differs, and every alarm is treated as an attack (they
cannot separate flash crowds). Detection is evaluated from the detector's
labels independently of mitigation (table A of `summary.md`); mitigation and
network impact are reported per configuration (table B).

### Metrics (all from recorded data; units in the metric names)

| Metric | Source and method | Unit |
|---|---|---|
| TP/FP/FN/TN, precision, recall, F1, FPR, FNR | `decisions.csv` vs ground truth: attack interval = first..last packet of the attack hosts (pauses included); row T covers traffic (T−3, T−2] (Member 3's measured 2-s lag). Positive = `naive_ddos`/`adaptive_ddos`. Rows from h6 start to stop | windows, ratio |
| Detection latency | first attack-labelled row with T ≥ attack start, minus attack start | s |
| Mitigation response time | first Barrier-confirmed limit (switch applied it) minus attack start | s |
| Decision → rule applied | Barrier reply time minus the time our app read the decision | ms |
| Release delay | last confirmed removal minus last attack packet | s |
| Rate limits / OpenFlow rules installed | `events.csv` (`limit_sent`; 1 meter + 1 flow each) | count |
| Legitimate / attack hosts limited | limited ports mapped to hosts via the Mininet port map | hosts |
| Packet delivery ratio (PDR) | packets received at h1's sink / packets sent (Member 1 logs), per role, binned in whole seconds over the focus interval | ratio |
| Throughput | packets (and UDP payload kbit) received at h1 per second, per role | pkt/s, kbit/s |
| Legitimate traffic during mitigation | h6 PDR and received rate during the attack, vs before it | ratio, pkt/s |
| Ping RTT / loss (h6→h1) | `ping -D` output, whole run and during the attack | ms, % |
| Flow-table occupancy | Member 2 `FlowTableOccupancy` (max, mean) | entries |
| Packet-In messages | Member 2 `PacketInRate` × 1-s window, summed | messages |
| Controller / detector CPU | psutil `cpu_percent`, 1-s samples | % of one core |
| Controller / detector memory | psutil RSS, 1-s samples | MiB |
| Experiment duration | run start to end | s |

"Focus interval" = attack interval in attack runs, scenario interval otherwise.

## Results (2026-10-23)

Recorded: the 24-run matrix (6 traffic setups × proposed / no-mitigation /
threshold-only / CUSUM-only), 6 entropy-only runs, and 3 extra runs (two
naive, one adaptive-moderate) started from the terminal and the dashboard —
33 complete runs. Full tables: `results/summary.md` (live runs, per
configuration) and `results/offline_detection.md` (all four detectors
replayed on the same recorded features). Every number below comes from
those files; most configurations have one run, so these are single
observations without confidence intervals.

**Detection on identical traffic (replay, 33 runs, windows pooled)**

| Detector | Precision | Recall | F1 | FPR | False-alarm windows on flash crowds |
|---|---|---|---|---|---|
| combined (proposed) | 0.875 | 0.656 | 0.750 | 0.042 | 0 |
| threshold-only | 0.832 | 0.666 | 0.740 | 0.061 | 96 |
| CUSUM-only | 0.690 | 0.912 | 0.786 | 0.186 | 114 |
| entropy-only | 0.192 | 0.007 | 0.013 | 0.013 | 2 |

The replayed combined decisions equal the live decisions in 15 of 15 runs.

**Mitigation (live runs)**

- **Naive DDoS.** With the proposed configuration the four attackers were
  metered on average 2.3 s after the attack started (3 runs); traffic
  delivered from them fell from 323.7 pkt/s (no mitigation) to 71.7 pkt/s
  (attack PDR 0.224) while the legitimate client h6 kept PDR 1.000.
  Threshold- and CUSUM-only behave alike here.
- **Flash crowd.** The combined detector raised no attack and limited no
  host (legitimate PDR 1.000). Threshold-only and CUSUM-only treated the
  crowd as an attack and limited the three legitimate hosts: legitimate PDR
  0.319 and 0.371. This is the main benefit of the combined detector.
- **Adaptive, aggressive / moderate.** Mitigation reduced attack PDR to
  0.169 / 0.597 (combined). The combined detector reacts later (response
  17.8 s for moderate) because it recognises the attack only at the second
  burst. The single-signal detectors react faster but (a) cannot spare flash
  crowds and (b) lifted mitigation during the attacker's pauses in 3 of
  their 4 moderate/aggressive runs (`released_before_attack_end`), so each
  new burst started unlimited; the combined detector's hold kept it on.
- **Adaptive, subtle.** Not mitigated by the combined, CUSUM or entropy
  configurations (attack PDR 1.000) and only after 34.3 s by threshold-only:
  at about 25 pkt/s in total it stays under the rate limits — the evasion
  the project studies.
- **Entropy-only.** Alarms only in single flow-setup windows, so it barely
  mitigates (attack PDR 0.953 naive, 0.994 aggressive) and releases before
  the attack ends; consistent with its replay recall of 0.007.
- **Collateral.** No legitimate host was limited in any attack run
  (`legit_hosts_limited` = 0); h6's ping showed no loss.
- **Switch-side check.** In all 7 complete runs recorded with the
  `ovs-ofctl` sampler (`ovs.csv`), the switch's own count of our flows and
  meters equalled the number of limits the app logged (0, 1 or 4) and was 0
  at the end of every run; e.g. the meters dropped 5,020 attack packets in
  the dashboard-started naive run.
- **Overhead.** Controller CPU averaged 0.4–4.1 % of one core, memory about
  46 MiB, with or without mitigation.

Caveats specific to these runs:
- Combined-detector recall (0.656 replay) is lower than Member 3's offline
  figure on their recorded runs (0.704), mainly from late/no detection of
  adaptive attacks, which now include subtle and aggressive levels.
- The background client h6 raises normal load to about 30 pkt/s, above the
  20 pkt/s baseline Member 3 calibrated on 2-host normal traffic. CUSUM-only
  therefore alarms during normal runs; mitigation then found no offender
  (all hosts ≤ 10 pkt/s), so no host was limited.
- `release_delay_s` includes Member 3's 6-window hold for adaptive attacks.

## Limitations

- **Late adaptive detection.** Member 3 labels the first burst of an adaptive
  attack `flash_crowd`; mitigation starts only at the second burst. The
  traffic of that first burst is delivered unmitigated.
- **Rate-only attribution.** Offenders are hosts sending ≥ 20 pkt/s while an
  attack is declared. A legitimate heavy sender active during an attack can be
  limited (counted as `legit_hosts_limited`). Not robust to spoofing; one host
  per switch port is assumed (true in this topology).
- **Coarse release.** Rules are removed together when the policy stops;
  Member 3's `hold` adds about 6 windows of mitigation after an adaptive attack.
- **No controller-side FlowMod throttling** (would need changes to Member 1's
  controller); Packet-In reduction applies only to limited ports.
- **Single testbed, small topology, few repeats.** Results come from one
  machine and 1 switch / 6 hosts; use `REPEATS` for averages. Member 3's
  thresholds were tuned on the recorded runs.
- **No comparison with published ML systems** is made here; different
  datasets, hardware and metrics make such numbers incomparable.

## Completion checklist

- [x] Decision interface with validation (`decisions.py`), live following
- [x] Configurable policy (`config.py`, per-run overrides)
- [x] OpenFlow meters + flow rules, verified supported on this OVS
- [x] Offender attribution from port statistics
- [x] Rule removal on release, cleanup on reconnect / detector restart
- [x] Logging of decisions, actions, OpenFlow events, port rates
- [x] Metric collection (detection, mitigation, network, resources)
- [x] Baseline detectors (threshold-only, CUSUM-only, entropy-only) and no-mitigation baseline
- [x] Detector comparison on identical recorded features (`offline_detection.py`)
- [x] Switch-side verification of installed rules and meter drops (`ovs.csv`)
- [x] Dashboard control mode (start / stop / cleanup)
- [x] Automated experiment runner and comparison
- [x] Unit / API tests (see TEST_REPORT.md)
- [x] Live demo dashboard (read-only, separate process)
- [x] Experiments run on the testbed (33 complete runs, `results/`)
- [x] Results summarised (`results/summary.md`, Results section above)
- [ ] Repeat the matrix (`REPEATS=3`) for averages
- [ ] Interface choices confirmed with Member 3

# Architecture

Rate-Limiting and Threshold-Based DDoS Mitigation in SDN — how the four
members' modules, the SDN testbed and the dashboard fit together.

## Components and data flow

```
                         Browser: http://127.0.0.1:8050/
                         (member4_mitigation/dashboard/index.html, plain JS)
                                   |  polls JSON every 1-2 s (HTTP GET)
                                   |  POST start/stop/cleanup only in --control mode
                                   v
       +-------------------------------------------------------------+
       | Dashboard server  member4_mitigation/dashboard/server.py    |
       | (Python stdlib http.server, localhost only)                 |
       |  state.py  : READS run files -> snapshot JSON               |
       |  control.py: launches run_experiment.py (--control only)    |
       +-------------------------------------------------------------+
              | reads files only                  | launches (sudo)
              v                                   v
  member4_mitigation/results/<run>/      member4_mitigation/run_experiment.py
  meta.json decisions.csv actions.csv    (one complete labelled experiment)
  events.csv port_stats.csv sink.csv            |
  ovs.csv resources.csv features.csv            | starts / stops
  traffic/*.csv metrics.json                    v
              ^              +--------------------------------------------------+
              | writes       | ONE os-ken (Ryu fork) controller process, OF 1.3 |
              +--------------|  Member 1  controller/simple_switch_13.py        |
                             |            learning switch, permanent flows      |
                             |  Member 2  sdn-ddos-monitoring/monitor.py        |
                             |            1-s feature vector -> features.csv    |
                             |  Member 4  member4_mitigation/mitigation_app.py  |
                             |            decisions -> meters + flow rules      |
                             +--------------------------------------------------+
                                   ^  OpenFlow 1.3 (TCP 6653)    |
                                   |  Packet-In, stats replies    | FlowMod, MeterMod,
                                   |                              | Barrier, stats requests
                             +--------------------------------------------------+
                             |  Open vSwitch s1 (Mininet), OpenFlow 1.3, meters |
                             +--------------------------------------------------+
                               |      |      |      |      |      |
                              h1     h2     h3     h4     h5     h6
                            victim   scenario hosts (Member 1      legitimate
                            + sink   generators: normal, flash     background
                                     crowd, naive, adaptive)       client + ping

  Member 3  detection/live_detector.py (separate process): follows features.csv,
            writes one decision per window to decisions.csv  -> read by Member 4 app.
  Baselines member4_mitigation/baseline_detectors.py: same live loop, threshold-only /
            CUSUM-only / entropy-only classifier.
```

## Interfaces (all files are CSV with a header row, one row per event/window)

| From → To | File / channel | Content |
|---|---|---|
| Member 1 → evaluation | `traffic/*.csv` | one row per packet SENT: timestamp, scenario, source/destination host, rates, flow id, attack level, feint state (`docs/MEMBER1_INTERFACE.md`) |
| Member 2 → Member 3 | `sdn-ddos-monitoring/data/features.csv` (moved into the run folder at the end) | one row per 1-s window: PacketInRate, FlowCreationRate, SourceIPEntropy, MeanIAT, Jitter, FlowTableOccupancy, ControllerRequestRate, HalfOpenTCPRatio (empty), DataPlanePacketRate |
| Member 3 → Member 4 | `decisions.csv` | `timestamp, traffic_class, score, reason, rule`; classes normal / flash_crowd / naive_ddos / adaptive_ddos / unknown |
| Member 4 → switch | OpenFlow 1.3 | per offending port: meter (drop band, pkt/s) + flow `in_port=P → meter P → output:NORMAL`, priority 100, cookie 0x4d34; Barrier to confirm |
| Member 4 → logs | `actions.csv`, `events.csv`, `port_stats.csv` | policy action per decision; rules sent / confirmed / removed / errors; per-port packet rates |
| Measurement | `sink.csv`, `ping_h6.txt`, `resources.csv`, `ovs.csv` | packets received at h1 per second & source; ping RTT; controller/detector CPU & memory; the switch's own flow/meter counts (`ovs-ofctl`) |
| Evaluation | `metrics.json`, `results/summary.*`, `results/offline_detection.*` | metrics per run; comparison across runs; detector replay on identical features |
| Dashboard | HTTP JSON (`/api/state`, `/api/summary`, `/api/control`, `/api/health`, `/api/runs`) | built from the files above; nothing is cached or invented |

## Timing of one run (run_experiment.py)

1. Controller (+monitor, +mitigation app) and detector start as the normal user.
2. Mininet: 1 OVS switch (OpenFlow 1.3), h1..h6; switch connects.
3. 10 s warm-up; then sink on h1, legitimate client h6 (10 pkt/s) and ping start.
4. 15 s later the scenario traffic starts on its hosts (Member 1 generators).
5. 25 s cool-down after the scenario ends (release is observed), then everything
   stops, `features.csv` is moved into the run folder, `metrics.json` is written.

## Where the four objectives are handled

| Objective | Mechanism | Where |
|---|---|---|
| Limit data-plane traffic | per-offender OpenFlow meter, drop above 10 pkt/s | `flow_rules.py` |
| Reduce Packet-In | limited ports match our rule, not the table-miss rule | `flow_rules.py` |
| Limit flow-table growth | ≤ 1 flow + 1 meter per limited port, capped by `MAX_LIMITED_PORTS` | `mitigation_app.py` |
| Controller-side FlowMod throttling | not implemented (would require changing Member 1's controller) | — |

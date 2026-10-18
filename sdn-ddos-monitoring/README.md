# Member 2 - Traffic monitoring and feature extraction

Part of the project "Rate-Limiting and Threshold-Based DDoS Mitigation in SDN".
This module is the monitoring stage only. It does NOT do detection, thresholds,
CUSUM, classification, machine learning, blocking, mitigation, L7 or DPI. It does
not use scenario names. Member 1's logs are used for validation only, never as
feature input.

## What it does
An os-ken (Ryu fork) application watches the OpenFlow 1.3 messages from the switch
and writes one feature vector per observation window (default 1 s) to
data/features.csv.

## Files
- monitor.py: os-ken app; counts events, polls the switch counters, builds the vector
- features.py: pure functions shannon_entropy and iat_stats
- csv_logger.py: CSV writer (fixed header, LF line endings, flushed per row)
- config.py: WINDOW_SIZE (default 1), FLOW_IDLE_TIMEOUT (30), CSV_PATH
- tests/: unit tests, CSV format check, comparison with Member 1's ground truth
- docs/METHODOLOGY.md: method, validation results, limitations (for the paper)
- validation/: Member 1's logs from our runs (validation only)
- data/: output CSVs (features_<scenario>.csv are the per-scenario runs)

## Requirements
Ubuntu with Mininet 2.3.0 and Open vSwitch (OpenFlow 1.3), Python 3.14, and the
packages in requirements.txt (our virtual environment is .venv-osken).

## Run (3 terminals)
Terminal A (venv active):

    cd ~/member2_monitoring && source .venv-osken/bin/activate
    PYTHONPATH=$HOME/member1_traffic:$HOME/member2_monitoring python3 ~/member1_traffic/tools/osken_run.py controller.simple_switch_13 monitor 2>&1 | tee run.log

Terminal B (no venv):

    cd ~/member1_traffic && sudo python3 topo/basic_topo.py

Then generate traffic at the mininet> prompt (see Member 1's docs). Stop with Ctrl+C
in Terminal A (the "HubThread has no attribute kill" message is a harmless
shutdown quirk) and type exit in Terminal B, then run: sudo mn -c

Every controller start renames an existing data/features.csv to
features_<modification time>.csv and starts a new file. To keep a scenario run,
copy data/features.csv to data/features_<scenario>.csv after the run.

## Output: CSV interface for Member 3
One row per window, fixed column order. Load with pandas.read_csv("data/features.csv").

| Column | Meaning |
|---|---|
| timestamp | Window END time, Unix epoch seconds (3 decimals), from a fixed clock |
| PacketInRate | All Packet-In messages in the window / WINDOW_SIZE (includes IPv6 chatter) |
| FlowCreationRate | New (src IP, dst IP) pairs seen in IPv4/ARP Packet-Ins / WINDOW_SIZE; a pair is new again after FLOW_IDLE_TIMEOUT |
| SourceIPEntropy | Shannon entropy (log2) of source IPs of IPv4/ARP Packet-Ins in the window; 0 for no or one source |
| MeanIAT | Mean gap (s) between consecutive IPv4/ARP Packet-In events; 0.0 if fewer than 2 events |
| Jitter | Population std dev (s) of those gaps; 0.0 if fewer than 2 events (0 does NOT always mean regular) |
| FlowTableOccupancy | Flow entries in the switch (includes the table-miss entry, so idle = 1); latest reply, up to one window old |
| ControllerRequestRate | (Packet-In + Echo Request + Port Status + Flow Removed + Error) / WINDOW_SIZE; almost always equals PacketInRate in this topology (it differed in 0 to 3 rows per run) |
| HalfOpenTCPRatio | Always empty (NaN): the dataset has no TCP traffic |
| DataPlanePacketRate | EXTRA column: packets the switch forwarded or sent to the controller per second (change in the aggregate packet counter); up to one window old |

Notes for Member 3:
- Rows start after the first switch connects. Idle windows are written as zero rows.
- The first window or two of a run can show DataPlanePacketRate 0 (no earlier counter to compare).
- After the flows are installed, the Packet-In based columns stay near 0 even during a
  flood, because Member 1's controller installs permanent flows. In our runs the only
  columns that follow traffic volume are DataPlanePacketRate and FlowTableOccupancy.
  MeanIAT and Jitter are computed from Packet-In events, so they are mostly 0.
- The extra column DataPlanePacketRate still needs Member 3's agreement.

## Tests
    cd ~/member2_monitoring
    python3 -m unittest discover -s tests -v
    python3 tests/check_csv_format.py
    bash tests/check_scenario.sh <scenario>   # after a scenario run; compares with validation/<scenario>/

## Open team decisions
- Add DataPlanePacketRate as an extra column (Member 3).
- Add idle_timeout to the flows in Member 1's controller so Packet-In features keep
  reacting after setup (Members 1 and 4; it changes the controller, not this module).
- Member 1's generators send below the configured rate (for example --rate=200 gave
  about 160 packets/s on one host).

## Completion checklist
- [x] Features: Packet-In rate, flow creation, source IP entropy, IAT/jitter, flow table occupancy, controller request rate
- [x] HalfOpenTCPRatio kept in the header, empty (no TCP in the dataset)
- [x] Fixed-clock windows, one CSV row per window, loads in pandas
- [x] Validated against Member 1's logs for normal, flash_crowd, naive_ddos, adaptive_ddos
- [ ] Member 3 agrees to the extra column
- [ ] Team decision on flow idle timeouts

# Monitoring and feature extraction: method and limitations (Member 2)

## Setting
Mininet topology with one OpenFlow 1.3 switch (Open vSwitch), six hosts, and an
os-ken learning-switch controller. The learning switch installs permanent flows
that match only (in_port, eth_src, eth_dst). The monitor is a second os-ken
application running in the same controller process. It is read-only: it does not
install, change or remove flows.

## Observation windows
A fixed-clock schedule ends window N at start + N x WINDOW_SIZE (default 1 s), where
start is the moment the first switch connects. The row timestamp is the window end.
In our runs consecutive timestamps were exactly 1.000 s apart.

## Features
Controller-side events (from Packet-In messages):
- PacketInRate, FlowCreationRate, SourceIPEntropy, MeanIAT, Jitter, ControllerRequestRate
  (definitions in README.md).
- Only IPv4 and ARP Packet-Ins feed flow creation, entropy and inter-arrival times.
  IPv6 is counted in PacketInRate but excluded elsewhere.
Switch-side counters (from an aggregate flow-statistics request sent once per window):
- FlowTableOccupancy = flow_count of the reply.
- DataPlanePacketRate = change in packet_count between consecutive replies / WINDOW_SIZE
  (negative changes are set to 0).
HalfOpenTCPRatio is not measured: the generators use UDP only and the switch flows do
not expose TCP flags to the controller. The column is kept empty so the interface is
unchanged.

## Validation against ground truth
Member 1's CSV logs (one row per packet sent) were used only to check the monitor.
For each scenario we counted packets per 1 s window from the logs and compared them
with DataPlanePacketRate.

| Scenario | Hosts | Ground-truth packets | Sum of DataPlanePacketRate | Mean abs diff, same window | Mean abs diff, previous window |
|---|---|---|---|---|---|
| normal | 2 | 585 | 597 | 2.0 | 0.6 |
| flash_crowd | 3 | 2831 | 2843 | 16.2 | 5.3 |
| naive_ddos | 4 | 6988 | 7002 | 37.4 | 3.0 |
| adaptive_ddos | 4 | 2890 | 2902 | 31.6 | 10.9 |

The totals differ by 12 to 14 packets. This is likely caused by packets handled by the
table-miss entry (Packet-Ins), which the aggregate counter includes; this was not
tested separately. The per-window values line up better with the previous window,
which confirms that each reply is read one window late.
Steady levels seen in these runs: normal about 20 packets/s, flash crowd about 148,
naive DDoS about 350, adaptive DDoS up to about 165 with silent gaps of 3-4 s.

## Limitations
1. Packet-In features only see controller-visible events. Because flows are permanent
   after the first packet of a MAC pair, a flood produces almost no Packet-Ins, and
   PacketInRate, FlowCreationRate, SourceIPEntropy, MeanIAT, Jitter and
   ControllerRequestRate react mainly during flow setup.
2. MeanIAT and Jitter describe the spacing of Packet-In events, not of data packets.
   Jitter = 0 is ambiguous: it also appears when fewer than 2 events exist.
3. IPv6 packets are excluded from flow, entropy and inter-arrival features.
4. FlowTableOccupancy and DataPlanePacketRate lag by up to one window. Under heavy load
   the reply timing can also shift packets between neighbouring windows (seen once in
   the adaptive run, where one window read 61 against about 124-150 around it); totals
   stay correct.
5. No occupancy ratio: Open vSwitch gives no reliable maximum table size.
6. One switch only: with several switches the latest reply would overwrite the others.
7. No TCP in the dataset, so HalfOpenTCPRatio is empty.
8. ControllerRequestRate is almost identical to PacketInRate in this topology. It
   differed in 0 to 3 rows per run (normal 0, adaptive 1, flash crowd 2, naive 3),
   probably because of Echo Request or similar control messages. We did not identify
   the message type, so the two columns are nearly redundant.
9. Validation covers one topology and one run per scenario.

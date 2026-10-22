# Handoff notes

## For Member 4 (mitigation & evaluation)

The detector only **classifies**. It does not block traffic or modify flows.

### How to consume decisions

Option 1 — read the CSV (`data/decisions_<scenario>.csv`, header row, one row
per 1-second window):

    timestamp,traffic_class,score,reason,rule

Option 1b — live: run `python3 live_detector.py` next to the monitor; it appends
each decision to `data/decisions_live.csv` within a fraction of a second.

Option 2 — call it from Python, one window at a time, **in time order**
(the detector keeps state between windows):

    from loader import load_features
    from thresholds import calibrate
    from detector import Detector

    baseline = calibrate(load_features("../sdn-ddos-monitoring/data/features_normal.csv")[0])
    det = Detector(baseline)
    decision = det.process(feature_row)   # feature_row: dict like loader.py returns
    # decision = {"timestamp", "traffic_class", "score", "reason", "rule"}

### Classes and suggested handling (your call)

| traffic_class | Meaning | Suggested handling |
|---|---|---|
| normal | within normal range | no action |
| flash_crowd | high rate, gradual onset, no attack pattern | do not block; at most gentle rate limiting |
| naive_ddos | rate jumped by >= 140 packets/s in one window | mitigate |
| adaptive_ddos | repeated bursts with pauses | mitigate; see hold note |
| unknown | key feature missing in that window | no action, log it |

`score` is `max(rate/limit, CUSUM/h)`; above 1 means abnormal.
`rule` says which rule fired (`threshold`, `cusum`, `onset_jump`,
`repeat_burst`, `hold`, `missing_input`, `none`).

### Things you should know

1. **Hold rows.** After an adaptive pattern is recognised, windows with
   `rule = hold` are pauses inside the pattern (up to 6 windows after the last
   burst). Keeping mitigation active through them avoids releasing during a
   pause; it also causes about 6 false-positive windows after the attack ends.
2. **Late adaptive recognition.** The first burst of an adaptive attack is
   labelled `flash_crowd`; it becomes `adaptive_ddos` only when the second burst
   starts (measured latency 15 windows on the recorded run).
3. **2-window lag.** A row's decision describes traffic from about 2 seconds
   earlier. Account for this when computing your own timing metrics.
4. **Evaluation numbers** are in `README.md` and `evaluate.py` (in-sample, one
   run per scenario). Re-run `python3 evaluate.py` for the exact figures.

### Open questions for Member 4

- Is `timestamp, traffic_class, score, reason, rule` acceptable, or do you
  need different columns or a different file/streaming format?
- Should mitigation stay active during `hold` rows, or release?
- Do you want `unknown` rows passed through, or dropped?

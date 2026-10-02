# Member 1 → Member 2 Interface: Traffic/Attack Log Format

This is the contract for consuming Member 1's generated traffic data.
You should never need to read Member 1's generator source code --
everything you need to monitor and extract features is below.

## Where the data lives

Every scenario script writes its output under `logs/`, **one file per
generator process** (i.e. one file per physical Mininet host per run --
not one shared file). This is deliberate: multiple processes writing to
one shared file concurrently risks interleaved/corrupted rows, and
per-process files sidestep that entirely.

**To get the full picture of an experiment, read every file matching
`logs/*.csv` and concatenate them.** Don't assume one file = the whole
experiment.

## CSV schema

Every row is one packet actually sent. Columns, in order:

| Column | Type | Meaning |
|---|---|---|
| `timestamp` | float | Unix epoch seconds when this packet was sent |
| `scenario` | str | one of: `normal`, `flash_crowd`, `naive_ddos`, `adaptive_ddos` |
| `source_host` | str | Mininet host name, e.g. `"h2"` (**not** an IP -- see caveat below) |
| `destination_host` | str | Mininet host name, e.g. `"h1"` |
| `packet_rate` | float | target packets/sec configured for this flow at send time |
| `flow_rate` | int | number of flows **concurrently active on this source host** at send time |
| `inter_arrival_time` | float | seconds since this same source's previous packet |
| `jitter` | float | seconds of jitter applied to this packet's wait (can be negative) |
| `flow_id` | str | unique ID per logical flow -- group rows by this to reconstruct one flow's timeline |
| `attack_level` | str | one of: `none`, `naive`, `subtle`, `moderate`, `aggressive` |
| `feint_state` | str | one of: `none`, `attack`, `pause` (see feint caveat below) |

### Value meaning by scenario

| scenario | attack_level | feint_state | notes |
|---|---|---|---|
| `normal` | `none` | `none` | single steady flow, Step 3 |
| `flash_crowd` | `none` | `none` | multiple organic virtual users per host, Step 4 |
| `naive_ddos` | `naive` | `none` | fixed rate, near-zero jitter, synchronized onset, Step 5 |
| `adaptive_ddos` | `subtle`/`moderate`/`aggressive` | `attack`/`pause` | Steps 6-8 |

## The JSON sidecar (adaptive_ddos only)

`adaptive_ddos_traffic.py` writes a `.json` file next to its `.csv`
(same basename), recording the **fully resolved** configuration for
that run -- including which attack-level preset was used and every
knob it resolved to, plus the feint schedule:

```json
{
  "src_name": "h2", "dst_name": "h1", "dst_ip": "10.0.0.1",
  "attack_level": "moderate",
  "resolved_params": {
    "ramp_up": 8.0, "prob_start": 0.05, "prob_end": 0.6,
    "rate_min": 5.0, "rate_max": 15.0, "jitter": 0.15,
    "feint_pattern": "AAP", "attack_duration": 6.0, "pause_duration": 4.0,
    ...
  },
  "start_at": 1790961724.762
}
```

Use this to compute ground truth for an experiment (e.g. exactly when
each pause window should start/end) rather than re-deriving it by
eyeballing gaps in the CSV.

## Known caveats (read these before you debug something that isn't a bug)

1. **Pauses are invisible, not labeled.** During a feint `pause` phase,
   the attacker sends **nothing** -- no packets, no marker rows. You will
   see a gap in `timestamp` for that `flow_id`/host, not a row with
   `feint_state="pause"`. (In practice `feint_state` only ever appears
   as `"attack"` in actual rows, since nothing is logged while paused.)
   Use the JSON sidecar's `start_at` + `feint_pattern` + durations to
   compute exactly where pauses should fall, if you need ground truth
   rather than inferring gaps statistically.

2. **The Mininet CLI host-name substitution trap.** If you ever generate
   your own test traffic from the Mininet CLI, typing a bare host name
   as a plain argument (`--src-name h2`) gets silently replaced by that
   host's IP (`--src-name 10.0.0.2`) by Mininet itself, not by our
   scripts. Always use `--opt=value` (one token) when the value might
   collide with a host name. `validate_log.py` (below) specifically
   checks for this and will flag it as an ERROR if it slipped through.

3. **`flow_rate` is per-source-host, not global.** It's the count of
   concurrently active flows on the *sending* host at that instant, not
   the total across all attacking hosts. If you want aggregate
   concurrent-flow count across the whole experiment, sum per-host
   values bucketed by time yourself from the combined CSVs.

4. **Rows across different files are not globally time-sorted** until
   you concatenate and sort them yourself. Each individual file IS in
   send order (hence timestamp order) for that one process.

## Validating a log before you build on it

Run the validator against any file(s) before writing analysis code
against them -- it catches schema drift, the IP-vs-hostname bug, and
out-of-order timestamps automatically:

```bash
python3 trafficgen/validate_log.py logs/normal_h2.csv
python3 trafficgen/validate_log.py logs/*.csv
```

Exit code is non-zero if any file has errors (use `--strict` to also
fail on warnings).

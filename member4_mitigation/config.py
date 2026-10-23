"""Member 4 - mitigation settings. Change values here, not in the code.

Import as `from member4_mitigation import config` (Members 2 and 3 also have
a top-level config.py; the package prefix keeps them apart).

Every setting below can be overridden for one run with an environment
variable named M4_<SETTING>, e.g. M4_METER_RATE_PPS=5. run_experiment.py
does this through its --set NAME=VALUE option, so parameter sweeps never
need code edits.
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def _env(name, default):
    raw = os.environ.get("M4_" + name)
    if raw is None or raw == "":
        return default
    if isinstance(default, bool):
        return raw.strip().lower() in ("1", "true", "on", "yes")
    if isinstance(default, (set, frozenset)):
        return {x.strip() for x in raw.split(",") if x.strip()}
    return type(default)(raw)


# ---- Live input / output ----
# Member 3's live_detector.py appends one decision per window here.
DECISIONS_PATH = _env("DECISIONS", os.path.join(_HERE, "..", "detection", "data",
                                                 "decisions_live.csv"))
# Folder for our logs (actions.csv, events.csv, port_stats.csv), rewritten each start.
RUN_DIR = _env("RUN_DIR", os.path.join(_HERE, "logs"))
# Seconds between checks of DECISIONS_PATH for new rows.
POLL_INTERVAL = _env("POLL_INTERVAL", 0.2)

# ---- Policy (which decisions switch mitigation on/off) ----
# Classes from Member 3 that switch mitigation on.
# flash_crowd is deliberately absent: no mitigation for legitimate surges
# unless measurements show a protective cap is needed (add it here to test).
MITIGATE_CLASSES = _env("MITIGATE_CLASSES", {"naive_ddos", "adaptive_ddos"})

# Member 3's 'hold' rows are pauses inside an adaptive attack.
# True  = keep mitigation on through them (the next burst stays limited).
# False = treat them as non-attack windows.
KEEP_DURING_HOLD = _env("KEEP_DURING_HOLD", True)

# 'unknown' rows mean Member 3 had no input for that window.
# True  = keep whatever state we are in (neither start nor release).
# False = treat them as non-attack windows.
UNKNOWN_KEEPS_STATE = _env("UNKNOWN_KEEPS_STATE", True)

# Release mitigation only after this many consecutive non-attack windows.
# 1 = release on the first clean window. Raise it to make release more
# cautious (on top of Member 3's own 6-window hold for adaptive attacks).
RELEASE_AFTER_CLEAN_WINDOWS = _env("RELEASE_AFTER_CLEAN_WINDOWS", 1)

# ---- Enforcement ----
# False = "monitor only": the policy runs and is logged, but no OpenFlow
# rules are installed. Used as the no-mitigation baseline.
MITIGATION_ENABLED = _env("MITIGATION", True)

# Seconds between per-port counter requests to the switch.
PORT_STATS_INTERVAL = _env("PORT_STATS_INTERVAL", 1.0)

# Offender selection (only consulted while mitigation is on):
# a switch port is limited if its received packet rate reached
# OFFENDER_MIN_PPS at any point in the last OFFENDER_LOOKBACK_S seconds.
# The look-back keeps a pausing (adaptive) attacker selected during its pause.
# Default 20 = twice the per-host rate of the recorded normal traffic (10 pkt/s),
# so a host sending at normal rate is never limited.
OFFENDER_MIN_PPS = _env("OFFENDER_MIN_PPS", 20.0)
OFFENDER_LOOKBACK_S = _env("OFFENDER_LOOKBACK_S", 10.0)
# Never limit more than this many ports at once (bounds the rules we add).
MAX_LIMITED_PORTS = _env("MAX_LIMITED_PORTS", 8)
# Switch ports that are never limited (e.g. a server's port), comma-separated.
PROTECTED_PORTS = {int(p) for p in _env("PROTECTED_PORTS", set())}

# Each limited port gets an OpenFlow meter that DROPS packets above this rate.
# Default 10 = the per-host rate of normal traffic: an offender is cut back to
# what a normal client sends, not blocked, so a misjudged host keeps working.
METER_RATE_PPS = _env("METER_RATE_PPS", 10)
METER_BURST = _env("METER_BURST", 10)

# Our flow rules: tagged with this cookie so we can find and delete exactly
# ours, and placed above Member 1's learned flows (priority 1).
COOKIE = 0x4D34          # "M4"
RULE_PRIORITY = _env("RULE_PRIORITY", 100)

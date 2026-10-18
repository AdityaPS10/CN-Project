"""Member 2 - configuration. Change values here, not in monitor.py."""

# Observation window length in seconds.
WINDOW_SIZE = 1

# A (src, dst) pair not seen for this many seconds counts as a new flow again.
FLOW_IDLE_TIMEOUT = 30

# Where the feature CSV is written (absolute path next to this file).
import os
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "features.csv")

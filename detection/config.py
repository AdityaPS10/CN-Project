# Settings for the Member 3 detector.

# Columns Member 2 writes, in order.
EXPECTED_COLUMNS = [
    "timestamp", "PacketInRate", "FlowCreationRate", "SourceIPEntropy",
    "MeanIAT", "Jitter", "FlowTableOccupancy", "ControllerRequestRate",
    "HalfOpenTCPRatio", "DataPlanePacketRate",
]

# Features we expect to have real values. A missing value here is reported.
REQUIRED_FEATURES = [
    "PacketInRate", "FlowCreationRate", "SourceIPEntropy", "MeanIAT",
    "Jitter", "FlowTableOccupancy", "ControllerRequestRate",
    "DataPlanePacketRate",
]

# HalfOpenTCPRatio is always empty (no TCP in the dataset), so it is not
# required. It is kept as None, never filled with an invented value.

# ---- Threshold detector settings ----
# Feature -> factor. A window is flagged if value > factor * baseline median.
THRESHOLD_FEATURES = {"DataPlanePacketRate": 3.0}

# A window counts as "active traffic" (used for the baseline) only if
# DataPlanePacketRate is at least this many packets/s.
ACTIVE_MIN_RATE = 5.0

# ---- CUSUM settings ----
CUSUM_FEATURE = "DataPlanePacketRate"
CUSUM_K = 5.0        # slack: ignore excess below baseline + K (packets/s)
CUSUM_H = 40.0       # alarm level for the accumulated excess
CUSUM_CAP_FACTOR = 2.0   # S is never allowed above CAP_FACTOR * H

# ---- Classifier (fusion) settings ----
# Naive attack: the rate jumps by more than JUMP_FACTOR * baseline in ONE window.
NAIVE_JUMP_FACTOR = 7.0
# Adaptive attack: two high-rate bursts separated by a pause of
# MIN_PAUSE..MAX_PAUSE windows. Shorter gaps are treated as a dip inside one burst.
MIN_PAUSE = 3
MAX_PAUSE = 15
# After an adaptive pattern is recognised, keep the "adaptive" label for this
# many windows of silence, so a pause is not mistaken for the attack ending.
HOLD_WINDOWS = 6

# ---- Evaluation settings ----
# The feature row at index j describes traffic from ground-truth second j-LAG.
# Measured by correlating Member 2's DataPlanePacketRate with Member 1's packet
# logs (peak correlation at 2 in all four scenarios).
GROUND_TRUTH_LAG = 2

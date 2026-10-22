import statistics

from config import THRESHOLD_FEATURES, ACTIVE_MIN_RATE


def calibrate(rows):
    """Build a baseline from a run of NORMAL traffic.

    Only 'active' windows are used (idle windows are mostly zeros and would
    drag every median to 0). Returns {feature: median_value}.
    """
    active = [r for r in rows
              if r["DataPlanePacketRate"] is not None
              and r["DataPlanePacketRate"] >= ACTIVE_MIN_RATE]
    if not active:
        raise ValueError("No active windows found; cannot build a baseline")
    baseline = {}
    for feature in THRESHOLD_FEATURES:
        values = [r[feature] for r in active if r[feature] is not None]
        if not values:
            raise ValueError("No values for " + feature + " in active windows")
        baseline[feature] = statistics.median(values)
    return baseline


def check_row(row, baseline):
    """Compare one window against the baseline.

    Returns a list of reasons (empty list = nothing abnormal). Each reason is
    a dict: feature, value, limit. A missing value is skipped, not guessed.
    """
    reasons = []
    for feature, factor in THRESHOLD_FEATURES.items():
        value = row.get(feature)
        if value is None:
            continue
        limit = factor * baseline[feature]
        if value > limit:
            reasons.append({"feature": feature, "value": value, "limit": limit})
    return reasons

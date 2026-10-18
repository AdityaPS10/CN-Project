"""Member 2 - pure feature calculations (no os_ken here, so easy to test)."""
import math
from collections import Counter


def shannon_entropy(items):
    """H = -sum(p * log2(p)) over the distribution of items. Empty -> 0.0"""
    counts = Counter(items)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h + 0.0   # avoids printing -0.0


def iat_stats(timestamps, prev_ts=None):
    """Given sorted event timestamps (and the last timestamp of the previous
    window, if any), return (mean, min, max, jitter) of inter-arrival times.
    Jitter = population standard deviation of the IATs. No IATs -> all 0.0."""
    ts = list(timestamps)
    if prev_ts is not None:
        ts = [prev_ts] + ts
    iats = [b - a for a, b in zip(ts, ts[1:])]
    if not iats:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(iats) / len(iats)
    var = sum((x - mean) ** 2 for x in iats) / len(iats)
    return mean, min(iats), max(iats), math.sqrt(var)

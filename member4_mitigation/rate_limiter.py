"""Member 4 - decides WHICH switch ports to rate-limit (no OpenFlow here).

Member 3's decisions say *whether* an attack is happening, not *who* is
sending it. We find the senders ourselves from the switch's per-port
counters: rx_packets on a port = packets the attached host sent into the
switch. (One host per port in our topology, so port N = host hN.)

The rate on each port is the change in rx_packets between two polls. A port
counts as an offender if its rate reached OFFENDER_MIN_PPS at least once in
the last OFFENDER_LOOKBACK_S seconds; the look-back keeps an adaptive
attacker selected while it pauses.
"""
from collections import deque


class PortRateTracker:
    def __init__(self, min_pps, lookback_s, max_ports, protected_ports=()):
        self.min_pps = min_pps
        self.lookback_s = lookback_s
        self.max_ports = max_ports
        self.protected = set(protected_ports)
        self._last = {}       # (dpid, port) -> (time, rx_packets)
        self._history = {}    # (dpid, port) -> deque of (time, pps)

    def update(self, dpid, port, t, rx_packets):
        """Record one counter reading. Returns the rate in packets/s since
        the previous reading, or None for the first reading of a port."""
        key = (dpid, port)
        prev = self._last.get(key)
        self._last[key] = (t, rx_packets)
        if prev is None or t <= prev[0] or rx_packets < prev[1]:
            return None       # first sample, clock oddity, or counter reset
        pps = (rx_packets - prev[1]) / (t - prev[0])
        hist = self._history.setdefault(key, deque())
        hist.append((t, pps))
        while hist and hist[0][0] < t - self.lookback_s:
            hist.popleft()
        return pps

    def peak_rate(self, dpid, port, now):
        hist = self._history.get((dpid, port), ())
        rates = [pps for t, pps in hist if t >= now - self.lookback_s]
        return max(rates) if rates else 0.0

    def offenders(self, dpid, now):
        """Ports on this switch to limit, highest peak rate first."""
        found = []
        for (d, port) in self._history:
            if d != dpid or port in self.protected:
                continue
            peak = self.peak_rate(d, port, now)
            if peak >= self.min_pps:
                found.append((peak, port))
        found.sort(reverse=True)
        return [(port, peak) for peak, port in found[:self.max_ports]]

    def forget(self, dpid):
        """Drop all state for a switch (it disconnected)."""
        for key in [k for k in self._last if k[0] == dpid]:
            self._last.pop(key, None)
            self._history.pop(key, None)

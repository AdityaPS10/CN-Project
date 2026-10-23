import unittest

from member4_mitigation.rate_limiter import PortRateTracker


def feed(tr, port, samples, dpid=1):
    """samples: list of (t, rx_packets); returns list of rates."""
    return [tr.update(dpid, port, t, n) for t, n in samples]


class TestPortRateTracker(unittest.TestCase):
    def setUp(self):
        self.tr = PortRateTracker(min_pps=20, lookback_s=10, max_ports=2, protected_ports={1})

    def test_rate_is_counter_delta_over_time(self):
        self.assertEqual(feed(self.tr, 2, [(0, 0), (1, 50), (3, 70)]), [None, 50.0, 10.0])

    def test_counter_reset_gives_no_rate(self):
        self.assertEqual(feed(self.tr, 2, [(0, 100), (1, 5)]), [None, None])

    def test_normal_rate_host_is_not_an_offender(self):
        feed(self.tr, 6, [(t, 10 * t) for t in range(6)])          # 10 pkt/s
        self.assertEqual(self.tr.offenders(1, 5), [])

    def test_attacker_is_offender_highest_first(self):
        feed(self.tr, 2, [(t, 30 * t) for t in range(4)])
        feed(self.tr, 3, [(t, 90 * t) for t in range(4)])
        feed(self.tr, 6, [(t, 10 * t) for t in range(4)])
        self.assertEqual([p for p, _ in self.tr.offenders(1, 3)], [3, 2])

    def test_pausing_attacker_stays_selected_within_lookback(self):
        feed(self.tr, 2, [(0, 0), (1, 50), (2, 50), (3, 50), (4, 50)])   # burst, then silent
        self.assertEqual([p for p, _ in self.tr.offenders(1, 4)], [2])
        feed(self.tr, 2, [(12, 50)])                                      # burst now >10 s old
        self.assertEqual(self.tr.offenders(1, 12), [])

    def test_protected_port_never_selected(self):
        feed(self.tr, 1, [(t, 500 * t) for t in range(3)])
        self.assertEqual(self.tr.offenders(1, 2), [])

    def test_max_ports_cap(self):
        for port in (2, 3, 4):
            feed(self.tr, port, [(t, 100 * port * t) for t in range(3)])
        self.assertEqual(len(self.tr.offenders(1, 2)), 2)

    def test_switches_are_separate_and_forget_works(self):
        feed(self.tr, 2, [(t, 50 * t) for t in range(3)], dpid=7)
        self.assertEqual(self.tr.offenders(1, 2), [])
        self.assertEqual([p for p, _ in self.tr.offenders(7, 2)], [2])
        self.tr.forget(7)
        self.assertEqual(self.tr.offenders(7, 2), [])


if __name__ == "__main__":
    unittest.main()

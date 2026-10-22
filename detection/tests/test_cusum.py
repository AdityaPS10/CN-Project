import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cusum import Cusum


class TestCusum(unittest.TestCase):
    def test_normal_noise_never_alarms(self):
        c = Cusum(mu=20, k=5, h=40)
        for x in [18, 22, 20, 24, 19, 25, 21] * 20:
            _, alarm = c.update(x)
            self.assertFalse(alarm)

    def test_sustained_increase_alarms(self):
        c = Cusum(mu=20, k=5, h=40)
        alarms = [c.update(45)[1] for _ in range(5)]   # excess 20 per window
        self.assertEqual(alarms, [False, False, True, True, True])

    def test_gradual_ramp_alarms_before_fixed_threshold(self):
        c = Cusum(mu=20, k=5, h=40)
        ramp = [20 + i for i in range(1, 61)]          # 21 .. 80
        first = next(i for i, x in enumerate(ramp) if c.update(x)[1])
        fixed = next(i for i, x in enumerate(ramp) if x > 60)
        self.assertLess(first, fixed)

    def test_missing_value_leaves_state_unchanged(self):
        c = Cusum(mu=20, k=5, h=40)
        c.update(45)
        before = c.s
        c.update(None)
        self.assertEqual(c.s, before)

    def test_cap_lets_alarm_clear_quickly(self):
        c = Cusum(mu=20, k=5, h=40)
        for _ in range(100):
            c.update(300)
        self.assertEqual(c.s, c.cap)
        cleared = next(i for i in range(50) if not c.update(0)[1])
        self.assertLess(cleared, 5)

    def test_threshold_is_exclusive(self):
        c = Cusum(mu=20, k=5, h=40)
        c.update(70)                                   # S = 45 -> alarm
        self.assertTrue(c.s > c.h)


if __name__ == "__main__":
    unittest.main()

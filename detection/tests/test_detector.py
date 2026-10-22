import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import Detector

BASE = {"DataPlanePacketRate": 20.0}   # limit 60, jump limit 140


def run(values):
    det = Detector(BASE)
    out = []
    for i, v in enumerate(values):
        out.append(det.process({"timestamp": float(i),
                                "DataPlanePacketRate": v})["traffic_class"])
    return out


class TestDetector(unittest.TestCase):
    def test_steady_normal(self):
        self.assertEqual(set(run([20, 22, 18, 21] * 10)), {"normal"})

    def test_abrupt_jump_is_naive(self):
        classes = run([0, 0, 30, 330, 340, 350, 340])
        self.assertEqual(classes[3:], ["naive_ddos"] * 4)

    def test_smooth_ramp_is_flash_crowd(self):
        classes = run([0, 10, 25, 40, 62, 85, 105, 140, 150, 150, 150])
        self.assertIn("flash_crowd", classes)
        self.assertNotIn("naive_ddos", classes)
        self.assertNotIn("adaptive_ddos", classes)

    def test_two_bursts_with_pause_is_adaptive(self):
        burst = [70, 90, 120, 150]
        classes = run([0] * 3 + burst + [0] * 5 + burst + [0] * 3)
        self.assertIn("adaptive_ddos", classes)
        # first burst cannot be known as adaptive yet
        self.assertEqual(classes[3], "flash_crowd")

    def test_short_dip_is_not_a_second_burst(self):
        classes = run([0, 70, 90, 120, 30, 130, 150, 150, 0, 0])
        self.assertNotIn("adaptive_ddos", classes)

    def test_missing_value_gives_unknown_and_keeps_state(self):
        det = Detector(BASE)
        det.process({"timestamp": 0.0, "DataPlanePacketRate": 100.0})
        s_before = det.cusum.s
        d = det.process({"timestamp": 1.0, "DataPlanePacketRate": None})
        self.assertEqual(d["traffic_class"], "unknown")
        self.assertEqual(det.cusum.s, s_before)

    def test_value_just_below_and_above_limit(self):
        self.assertEqual(run([60.0])[0], "normal")
        self.assertNotEqual(run([60.1] * 5)[-1], "normal")

    def test_output_has_required_fields(self):
        d = Detector(BASE).process({"timestamp": 5.0,
                                    "DataPlanePacketRate": 20.0})
        self.assertEqual(set(d), {"timestamp", "traffic_class", "score",
                                  "reason", "rule"})


if __name__ == "__main__":
    unittest.main()

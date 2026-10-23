"""Tests for the measurement helpers and the baseline detectors."""
import os
import subprocess
import sys
import tempfile
import time
import unittest

from member4_mitigation.sink import SecondCounter
from member4_mitigation.baseline_detectors import ThresholdOnlyDetector, CusumOnlyDetector

BASELINE = {"DataPlanePacketRate": 20.0}     # Member 3's calibrated value


class TestSecondCounter(unittest.TestCase):
    def test_counts_per_second_and_source(self):
        c = SecondCounter()
        c.add(100.1, "10.0.0.2", 128)
        c.add(100.9, "10.0.0.2", 128)
        c.add(100.5, "10.0.0.6", 128)
        c.add(101.2, "10.0.0.2", 128)
        self.assertEqual(c.pop_before(101), [(100, "10.0.0.2", 2, 256), (100, "10.0.0.6", 1, 128)])
        self.assertEqual(c.pop_before(101), [])
        self.assertEqual(c.pop_before(float("inf")), [(101, "10.0.0.2", 1, 128)])


class TestBaselineDetectors(unittest.TestCase):
    def test_threshold_only_flags_any_rate_above_limit(self):
        det = ThresholdOnlyDetector(BASELINE)          # limit 3 x 20 = 60
        self.assertEqual(det.process({"timestamp": 1, "DataPlanePacketRate": 50})["traffic_class"], "normal")
        d = det.process({"timestamp": 2, "DataPlanePacketRate": 61})
        self.assertEqual((d["traffic_class"], d["rule"]), ("naive_ddos", "threshold"))

    def test_cusum_only_needs_sustained_excess(self):
        det = CusumOnlyDetector(BASELINE)              # mu 20, k 5, h 40
        classes = [det.process({"timestamp": i, "DataPlanePacketRate": 45})["traffic_class"]
                   for i in range(3)]                  # +20 per window: 20, 40, 60
        self.assertEqual(classes, ["normal", "normal", "naive_ddos"])

    def test_missing_value_is_unknown(self):
        for cls in (ThresholdOnlyDetector, CusumOnlyDetector):
            d = cls(BASELINE).process({"timestamp": 1, "DataPlanePacketRate": None})
            self.assertEqual(d["traffic_class"], "unknown")


class TestResourceMonitor(unittest.TestCase):
    def test_samples_a_process(self):
        try:
            from member4_mitigation.resource_monitor import ResourceMonitor
        except ImportError:
            self.skipTest("psutil not installed")
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"])
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            mon = ResourceMonitor({"child": child.pid}, path, interval=0.2)
            mon.start()
            time.sleep(1.0)
            mon.stop()
            with open(path) as f:
                lines = f.read().splitlines()
            self.assertEqual(lines[0], "wall_time,name,pid,cpu_percent,rss_mb")
            self.assertGreaterEqual(len(lines), 3)
            self.assertIn(",child,%d," % child.pid, lines[1])
        finally:
            child.kill()
            child.wait()
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

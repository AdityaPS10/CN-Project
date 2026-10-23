import os
import tempfile
import unittest

from member4_mitigation.decisions import parse_row, read_decisions

ROW = {"timestamp": "1791259924.07", "traffic_class": "normal", "score": "0.0",
       "reason": "within normal range", "rule": "none"}

HERE = os.path.dirname(os.path.abspath(__file__))
M3_DATA = os.path.join(HERE, "..", "..", "detection", "data")


class TestParseRow(unittest.TestCase):
    def test_normal_row(self):
        d = parse_row(ROW)
        self.assertEqual(d.traffic_class, "normal")
        self.assertFalse(d.is_attack)

    def test_hold_row_counts_as_attack(self):
        d = parse_row(dict(ROW, traffic_class="adaptive_ddos", rule="hold"))
        self.assertTrue(d.is_attack)

    def test_flash_crowd_is_not_attack(self):
        d = parse_row(dict(ROW, traffic_class="flash_crowd", rule="threshold"))
        self.assertFalse(d.is_attack)

    def test_unknown_class_rejected(self):
        with self.assertRaises(ValueError):
            parse_row(dict(ROW, traffic_class="ddos"))

    def test_bad_score_rejected(self):
        with self.assertRaises(ValueError):
            parse_row(dict(ROW, score="high"))


class TestReadDecisions(unittest.TestCase):
    def test_lf_and_crlf_files(self):
        for ending in ("\n", "\r\n"):
            text = ending.join(["timestamp,traffic_class,score,reason,rule",
                                "1.0,normal,0.0,ok,none",
                                '2.0,naive_ddos,2.1,"rate jumped 150, limit 140",onset_jump',
                                ""])
            with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as f:
                f.write(text)
            try:
                ds = read_decisions(f.name)
            finally:
                os.unlink(f.name)
            self.assertEqual(len(ds), 2)
            self.assertTrue(ds[1].is_attack)

    def test_member3_recorded_files_load(self):
        for scenario in ("normal", "flash_crowd", "naive_ddos", "adaptive_ddos"):
            ds = read_decisions(os.path.join(M3_DATA, "decisions_%s.csv" % scenario))
            self.assertGreater(len(ds), 0, scenario)


if __name__ == "__main__":
    unittest.main()

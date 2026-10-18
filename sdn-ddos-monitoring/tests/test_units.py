"""Unit tests for features.py and csv_logger.py. Run: python3 -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features import shannon_entropy, iat_stats
from csv_logger import CsvLogger, COLUMNS


class TestFeatures(unittest.TestCase):
    def test_entropy_empty_is_zero(self):
        self.assertEqual(shannon_entropy([]), 0.0)

    def test_entropy_single_source_is_zero(self):
        self.assertAlmostEqual(shannon_entropy(["a", "a", "a"]), 0.0)

    def test_entropy_two_equal_sources_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy(["a", "b"]), 1.0)

    def test_entropy_four_equal_sources_is_two_bits(self):
        self.assertAlmostEqual(shannon_entropy(["a", "b", "c", "d"]), 2.0)

    def test_entropy_three_to_one_split(self):
        self.assertAlmostEqual(shannon_entropy(["a", "a", "a", "b"]), 0.8113, places=4)

    def test_iat_no_events_is_all_zero(self):
        self.assertEqual(tuple(iat_stats([])), (0.0, 0.0, 0.0, 0.0))

    def test_iat_single_event_without_previous_is_all_zero(self):
        self.assertEqual(tuple(iat_stats([5.0])), (0.0, 0.0, 0.0, 0.0))

    def test_iat_single_event_with_previous(self):
        mean, mn, mx, jit = iat_stats([2.0], 1.0)
        self.assertAlmostEqual(mean, 1.0)
        self.assertAlmostEqual(mn, 1.0)
        self.assertAlmostEqual(mx, 1.0)
        self.assertAlmostEqual(jit, 0.0)

    def test_iat_three_events(self):
        mean, mn, mx, jit = iat_stats([1.0, 2.0, 4.0])
        self.assertAlmostEqual(mean, 1.5)
        self.assertAlmostEqual(mn, 1.0)
        self.assertAlmostEqual(mx, 2.0)
        self.assertAlmostEqual(jit, 0.5)


class TestCsvLogger(unittest.TestCase):
    def test_header_rows_and_line_endings(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            lg = CsvLogger(path)
            lg.write_row(["1.000", "0.00", "0.00", "0.0000", "0.000000",
                          "0.000000", "1", "0.00", "", "0.00"])
            lg.close()
            with open(path, "rb") as fh:
                raw = fh.read()
            self.assertNotIn(b"\r", raw)
            lines = raw.decode().splitlines()
            self.assertEqual(lines[0], ",".join(COLUMNS))
            self.assertEqual(len(lines), 2)
            self.assertEqual(len(lines[1].split(",")), 10)

    def test_wrong_field_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            lg = CsvLogger(os.path.join(d, "x.csv"))
            with self.assertRaises(AssertionError):
                lg.write_row(["1", "2"])
            lg.close()

    def test_existing_file_is_renamed_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            CsvLogger(path).close()
            CsvLogger(path).close()
            self.assertEqual(len(os.listdir(d)), 2)


if __name__ == "__main__":
    unittest.main()

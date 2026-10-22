import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from loader import load_features, parse_value
from config import EXPECTED_COLUMNS

HEADER = ",".join(EXPECTED_COLUMNS) + "\n"


def write_csv(body):
    f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
    f.write(HEADER + body)
    f.close()
    return f.name


class TestParse(unittest.TestCase):
    def test_values(self):
        self.assertEqual(parse_value("3.5"), 3.5)
        self.assertIsNone(parse_value(""))
        self.assertIsNone(parse_value("abc"))
        self.assertIsNone(parse_value("nan"))
        self.assertIsNone(parse_value(None))


class TestLoader(unittest.TestCase):
    def test_good_row(self):
        path = write_csv("100.0,1,0,0,0,0,1,1,,20\n")
        rows, problems = load_features(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(problems, [])
        self.assertIsNone(rows[0]["HalfOpenTCPRatio"])
        self.assertEqual(rows[0]["DataPlanePacketRate"], 20.0)

    def test_bad_timestamp_skips_row(self):
        path = write_csv("oops,1,0,0,0,0,1,1,,20\n")
        rows, problems = load_features(path)
        self.assertEqual(rows, [])
        self.assertEqual(len(problems), 1)

    def test_negative_and_missing(self):
        path = write_csv("100.0,-5,0,0,0,0,1,1,,\n")
        rows, problems = load_features(path)
        self.assertIsNone(rows[0]["PacketInRate"])
        self.assertIsNone(rows[0]["DataPlanePacketRate"])
        self.assertEqual(len(problems), 2)

    def test_missing_column_raises(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
        f.write("timestamp,PacketInRate\n1,2\n")
        f.close()
        with self.assertRaises(ValueError):
            load_features(f.name)


if __name__ == "__main__":
    unittest.main()

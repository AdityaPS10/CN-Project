import os
import tempfile
import unittest

from member4_mitigation.decisions import DecisionFollower

HEADER = "timestamp,traffic_class,score,reason,rule\n"


def row(t, cls="normal", rule="none"):
    return "%s,%s,0.0,r,%s\n" % (t, cls, rule)


class TestFollower(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        os.unlink(self.path)          # start with no file

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def write(self, text, mode="a"):
        with open(self.path, mode) as f:
            f.write(text)

    def test_missing_file_is_not_an_error(self):
        self.assertEqual(DecisionFollower(self.path).poll(), ([], []))

    def test_existing_rows_are_skipped_new_rows_read(self):
        self.write(HEADER + row(1) + row(2), "w")
        f = DecisionFollower(self.path)
        self.assertEqual(f.poll()[0], [])
        self.write(row(3, "naive_ddos", "onset_jump"))
        ds, _ = f.poll()
        self.assertEqual([d.timestamp for d in ds], [3.0])
        self.assertTrue(ds[0].is_attack)

    def test_file_created_after_start_is_read_from_top(self):
        f = DecisionFollower(self.path)
        f.poll()
        self.write(HEADER + row(1), "w")
        # first open happens now, so existing rows are skipped...
        self.assertEqual(f.poll()[0], [])
        self.write(row(2))
        self.assertEqual(len(f.poll()[0]), 1)

    def test_half_written_line_waits(self):
        self.write(HEADER, "w")
        f = DecisionFollower(self.path)
        f.poll()
        self.write("5,normal,0.0,r,")
        self.assertEqual(f.poll()[0], [])
        self.write("none\n")
        self.assertEqual([d.timestamp for d in f.poll()[0]], [5.0])

    def test_truncation_is_reported_and_reread(self):
        self.write(HEADER + row(1) + row(2) + row(3), "w")
        f = DecisionFollower(self.path)
        f.poll()
        self.write(HEADER + row(10), "w")     # detector restarted
        ds, notes = f.poll()
        self.assertEqual([n[0] for n in notes], ["reset"])
        self.assertEqual([d.timestamp for d in ds], [10.0])

    def test_bad_row_is_skipped_not_fatal(self):
        self.write(HEADER, "w")
        f = DecisionFollower(self.path)
        f.poll()
        self.write(row(1, "ddos") + row(2))
        ds, notes = f.poll()
        self.assertEqual([d.timestamp for d in ds], [2.0])
        self.assertEqual([n[0] for n in notes], ["bad_row"])


if __name__ == "__main__":
    unittest.main()

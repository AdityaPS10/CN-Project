"""Dashboard snapshot: must never crash and never write (SYNTHETIC inputs)."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard"))
import state  # noqa: E402


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


class TestDashboardState(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.run = os.path.join(self.root, "20260101_000000_naive_ddos_combined_mit-on")
        os.makedirs(self.run)
        write(os.path.join(self.run, "meta.json"), json.dumps({
            "run_id": "r", "scenario": "naive_ddos", "detector": "combined", "mitigation": "on",
            "status": "running", "t_run_start": 1000.0, "t_scenario_start": 1010.0,
            "attack_hosts": ["h2"], "legit_hosts": ["h6"], "server": "h1",
            "port_map": {"1": "h1", "2": "h2", "6": "h6"},
            "host_ips": {"h1": "10.0.0.1", "h2": "10.0.0.2", "h6": "10.0.0.6"}}))
        write(os.path.join(self.run, "decisions.csv"),
              "timestamp,traffic_class,score,reason,rule\n"
              "1011,normal,0.1,ok,none\n1012,naive_ddos,5.0,jump,onset_jump\n1013,naive_dd")  # half line
        write(os.path.join(self.run, "actions.csv"),
              "wall_time,decision_timestamp,traffic_class,rule,score,action,mitigation_active,why\n"
              "1011.1,1011,normal,none,0.1,none,0,x\n1012.1,1012,naive_ddos,onset_jump,5,start,1,x\n")
        write(os.path.join(self.run, "events.csv"),
              "wall_time,event,dpid,ports,detail\n"
              "1000.5,app_started,,,enforcement=True meter_rate_pps=10 offender_min_pps=20.0\n"
              "1012.2,limit_sent,1,2,peak_pps=90\n")
        write(os.path.join(self.run, "port_stats.csv"),
              "wall_time,dpid,port,rx_packets,rx_pps\n"
              "1011,1,2,10,\n1012,1,2,100,90\n1012,1,6,20,10\n1012,1,1,5,3\n")
        write(os.path.join(self.run, "sink.csv"),
              "second,src_ip,packets,bytes\n1010,10.0.0.2,50,6400\n1012,10.0.0.2,10,1280\n")
        self.files_before = {f: os.path.getmtime(os.path.join(self.run, f)) for f in os.listdir(self.run)}

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_snapshot_contents(self):
        s = state.build_state(self.run, now=1015.0)
        self.assertTrue(s["run"]["live"])
        self.assertEqual(s["decision"]["cls"], "naive_ddos")        # half line ignored
        self.assertEqual(len(s["decisions"]), 2)
        self.assertTrue(s["mitigation"]["active"])
        self.assertEqual(s["mitigation"]["limited"], ["h2"])
        self.assertEqual(s["mitigation"]["spans"], [[12.1, None]])
        self.assertEqual(s["mitigation"]["meter_rate_pps"], 10.0)
        self.assertNotIn("h1", s["series"]["port_rate"])            # victim port hidden
        self.assertEqual(s["series"]["port_rate"]["h2"], [[12.0, 90.0]])
        # sink second 1011 had no row -> filled with 0
        self.assertEqual(s["series"]["victim_rx"]["h2"], [[11.0, 50], [12.0, 0], [13.0, 10]])
        self.assertEqual({h["name"]: h["role"] for h in s["hosts"]}, {"h2": "attacker", "h6": "legitimate"})
        self.assertEqual(s["warnings"], [])

    def test_never_writes(self):
        state.build_state(self.run, now=1015.0)
        after = {f: os.path.getmtime(os.path.join(self.run, f)) for f in os.listdir(self.run)}
        self.assertEqual(after, self.files_before)

    def test_missing_and_corrupt_files_do_not_crash(self):
        write(os.path.join(self.run, "meta.json"), "{not json")
        os.unlink(os.path.join(self.run, "sink.csv"))
        write(os.path.join(self.run, "port_stats.csv"), "\x00\x01garbage\nmore,garbage\n")
        s = state.build_state(self.run, now=1015.0)
        self.assertTrue(any("meta.json" in w for w in s["warnings"]))
        self.assertEqual(s["series"]["victim_rx"], {})
        empty = os.path.join(self.root, "empty")
        os.makedirs(empty)
        self.assertEqual(state.build_state(empty, now=1.0)["decision"], None)

    def test_run_ids_are_confined_to_results(self):
        self.assertIsNone(state.safe_run_dir(self.root, "../" + os.path.basename(self.root)))
        self.assertIsNone(state.safe_run_dir(self.root, ".."))
        self.assertIsNone(state.safe_run_dir(self.root, "/etc"))
        self.assertEqual(state.safe_run_dir(self.root, os.path.basename(self.run)), self.run)
        self.assertEqual([r["id"] for r in state.list_runs(self.root)], [os.path.basename(self.run)])


if __name__ == "__main__":
    unittest.main()

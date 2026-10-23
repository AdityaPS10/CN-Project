"""Evaluator + compare on a SYNTHETIC run folder (hand-made inputs, known answers).

Nothing here is experimental data; it only checks the metric arithmetic.
Story: attacker h2 sends 100 pkt/s during [1000, 1010); legit h6 sends
10 pkt/s throughout; the meter lets 10 pkt/s of h2 through from 1004 on.
"""
import csv
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

from member4_mitigation import evaluator, compare

M1_FIELDS = ["timestamp", "scenario", "source_host", "destination_host", "packet_rate",
             "flow_rate", "inter_arrival_time", "jitter", "flow_id", "attack_level", "feint_state"]


def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def make_run(d):
    os.makedirs(os.path.join(d, "traffic"))
    meta = {"run_id": "synthetic", "scenario": "naive_ddos", "attack_level": None,
            "detector": "combined", "mitigation": "on", "config_overrides": {},
            "attack_hosts": ["h2"], "legit_hosts": ["h6"], "legit_bg_host": "h6",
            "host_ips": {"h1": "10.0.0.1", "h2": "10.0.0.2", "h6": "10.0.0.6"},
            "port_map": {"1": "h1", "2": "h2", "6": "h6"},
            "t_run_start": 970.0, "t_bg_start": 990.0, "t_scenario_start": 1000.0,
            "t_scenario_end": 1010.0, "t_stop": 1030.0, "t_run_end": 1035.0}
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f)

    atk = [(1000 + i / 100.0) for i in range(1000)]                 # 100 pkt/s, 10 s
    leg = [(990 + i / 10.0) for i in range(400)]                    # 10 pkt/s, 40 s
    row = lambda t, h, sc: [t, sc, h, "h1", 1, 1, 0, 0, "f-" + h, "none", "none"]
    write_csv(os.path.join(d, "traffic", "naive_ddos_h2.csv"), M1_FIELDS, [row(t, "h2", "naive_ddos") for t in atk])
    write_csv(os.path.join(d, "traffic", "legit_h6.csv"), M1_FIELDS, [row(t, "h6", "normal") for t in leg])

    sink = [(s, "10.0.0.6", 10, 1280) for s in range(990, 1030)]
    sink += [(s, "10.0.0.2", 100 if s < 1004 else 10, (100 if s < 1004 else 10) * 128)
             for s in range(1000, 1010)]
    write_csv(os.path.join(d, "sink.csv"), ["second", "src_ip", "packets", "bytes"], sink)

    dec, act = [], []
    for ts in range(991, 1036):
        attack = 1003 <= ts <= 1013
        cls = "naive_ddos" if attack else "normal"
        dec.append([ts, cls, 2.0 if attack else 0.1, "r", "onset_jump" if attack else "none"])
        action = "start" if ts == 1003 else ("keep" if attack else ("stop" if ts == 1014 else "none"))
        act.append([ts + 0.05, ts, cls, "x", 0, action, int(attack), "w"])
    write_csv(os.path.join(d, "decisions.csv"), ["timestamp", "traffic_class", "score", "reason", "rule"], dec)
    write_csv(os.path.join(d, "actions.csv"), ["wall_time", "decision_timestamp", "traffic_class", "rule",
                                               "score", "action", "mitigation_active", "why"], act)
    write_csv(os.path.join(d, "events.csv"), ["wall_time", "event", "dpid", "ports", "detail"], [
        [1003.06, "limit_sent", "1", "2", "peak_pps=100"],
        [1003.5, "limit_confirmed", "1", "2", "switch_ms=2.0 decision_to_applied_ms=450.0"],
        [1014.1, "remove_sent", "1", "2", "policy_stop"],
        [1014.2, "remove_confirmed", "1", "2", "switch_ms=1.0"]])

    with open(os.path.join(d, "ping_h6.txt"), "w") as f:
        for i in range(10):
            f.write("[%.3f] 64 bytes from 10.0.0.1: icmp_seq=%d ttl=64 time=%.1f ms\n"
                    % (995 + i * 2, i + 1, 1.0 if i < 3 else 3.0))
        f.write("10 packets transmitted, 9 received, 10% packet loss, time 9000ms\n")

    write_csv(os.path.join(d, "features.csv"),
              ["timestamp", "PacketInRate", "FlowTableOccupancy", "DataPlanePacketRate"],
              [[ts, 2 if ts == 992 else 0, 5 if ts < 1004 else 6, 0] for ts in range(990, 1031)])
    write_csv(os.path.join(d, "resources.csv"), ["wall_time", "name", "pid", "cpu_percent", "rss_mb"],
              [[1000, "controller", 1, 10.0, 50.0], [1001, "controller", 1, 30.0, 52.0]])
    return d


class TestEvaluator(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.run = make_run(os.path.join(self.root, "synthetic"))
        self.m = evaluator.evaluate_run(self.run)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_detection_counts_use_lag(self):
        # truth rows: window (ts-3, ts-2] overlaps [1000, 1010) -> ts 1002..1012
        d = self.m["detection"]
        self.assertEqual((d["tp"], d["fn"], d["fp"]), (10, 1, 1))
        self.assertAlmostEqual(d["detection_latency_s"], 3.0)
        self.assertAlmostEqual(d["decision_received_latency_s"], 3.05)

    def test_mitigation_metrics(self):
        a = self.m["mitigation_actions"]
        self.assertEqual(a["limited_hosts"], ["h2"])
        self.assertEqual(a["legit_hosts_limited"], [])
        self.assertEqual(a["openflow_rules_installed"], 2)
        self.assertAlmostEqual(a["response_time_s"], 3.5)
        self.assertAlmostEqual(a["decision_to_rule_applied_ms"], 450.0)
        self.assertAlmostEqual(a["release_delay_s"], 1014.2 - 1009.99, places=3)
        self.assertFalse(a["released_before_attack_end"])

    def test_early_release_is_flagged_not_negative(self):
        # SYNTHETIC: mitigation lifted at 1005, attack ran until 1010.
        rows = open(os.path.join(self.run, "events.csv")).read().replace("1014.2,remove_confirmed", "1005.0,remove_confirmed")
        with open(os.path.join(self.run, "events.csv"), "w") as f:
            f.write(rows)
        a = evaluator.evaluate_run(self.run)["mitigation_actions"]
        self.assertIsNone(a["release_delay_s"])
        self.assertTrue(a["released_before_attack_end"])

    def test_traffic_pdr(self):
        t = self.m["traffic"]
        self.assertAlmostEqual(t["legit_during_focus"]["pdr"], 1.0)
        # attack: sent 1000; received 4*100 + 6*10 = 460
        self.assertEqual(t["attack_during_focus"]["sent_packets"], 1000)
        self.assertEqual(t["attack_during_focus"]["received_packets"], 460)
        self.assertAlmostEqual(t["attack_during_focus"]["pdr"], 0.46)

    def test_ping_switch_resources(self):
        self.assertAlmostEqual(self.m["ping_h6"]["loss_pct"], 10.0)
        self.assertEqual(self.m["switch"]["flow_table_max_entries"], 6)
        self.assertEqual(self.m["switch"]["packet_in_total"], 2)
        self.assertAlmostEqual(self.m["resources"]["controller"]["cpu_mean_pct"], 20.0)

    def test_summary_and_compare(self):
        self.assertIn("legit limited: none", evaluator.format_summary(self.m))
        evaluator.write_metrics(self.run, self.m)
        with redirect_stdout(io.StringIO()):
            import sys
            argv, sys.argv = sys.argv, ["compare", self.root]
            try:
                compare.main()
            finally:
                sys.argv = argv
        with open(os.path.join(self.root, "summary.md")) as f:
            text = f.read()
        self.assertIn("| combined | 1 | 10 | 1 | 1 |", text)
        self.assertTrue(os.path.exists(os.path.join(self.root, "summary.csv")))


if __name__ == "__main__":
    unittest.main()

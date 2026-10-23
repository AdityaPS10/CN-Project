"""Dashboard HTTP API tests (real server on a free localhost port).

Uses SYNTHETIC run folders. The control tests use a MOCK runner (a small
python script that stands in for run_experiment.py and just waits for
Ctrl+C), because the real runner needs root and Mininet.
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "dashboard"))
import control  # noqa: E402
import server  # noqa: E402

MOCK_RUNNER = """
import signal, sys, time
print('mock runner args:', sys.argv[1:], flush=True)
signal.signal(signal.SIGINT, lambda *a: (print('mock runner: got Ctrl+C, cleaning up', flush=True), sys.exit(130)))
while True:
    time.sleep(0.1)
"""


class ApiTestBase(unittest.TestCase):
    controller = None

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.results = os.path.join(self.root, "results")
        os.makedirs(os.path.join(self.results, "20260101_000000_normal_combined_mit-on"))
        with open(os.path.join(self.results, "20260101_000000_normal_combined_mit-on", "meta.json"), "w") as f:
            json.dump({"run_id": "synthetic", "scenario": "normal", "status": "finished",
                       "t_run_start": 1.0, "t_run_end": 2.0}, f)
        self.httpd = server.make_server("127.0.0.1", 0, results_dir=self.results,
                                        controller=self.make_controller())
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def make_controller(self):
        return None

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.root)

    def req(self, method, path, body=None, headers=None):
        h = {"Host": "127.0.0.1:%d" % self.port}
        if method == "POST":
            h.update({"X-M4-Request": "1", "Content-Type": "application/json"})
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, data


class TestReadOnlyApi(ApiTestBase):
    def test_page_and_health(self):
        status, body = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"SDN DDoS Mitigation", body)
        status, h = self.req("GET", "/api/health")
        self.assertEqual((status, h["ok"], h["control_enabled"], h["runs"]), (200, True, False, 1))

    def test_state_newest_and_unknown(self):
        status, s = self.req("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(s["run"]["id"], "synthetic")
        status, s = self.req("GET", "/api/state?run=does_not_exist")
        self.assertIn("unknown run", s["error"])
        status, s = self.req("GET", "/api/state?run=..%2F..%2Fetc")
        self.assertIn("unknown run", s["error"])

    def test_summary_without_metrics(self):
        status, s = self.req("GET", "/api/summary")
        self.assertEqual((status, s["runs"], s["offline_available"]), (200, [], False))

    def test_404_and_bad_host(self):
        self.assertEqual(self.req("GET", "/nope")[0], 404)
        self.assertEqual(self.req("GET", "/api/health", headers={"Host": "evil.example:80"})[0], 403)

    def test_post_refused_in_read_only_mode(self):
        status, body = self.req("POST", "/api/control/start", {"scenario": "normal"})
        self.assertEqual(status, 403)
        self.assertIn("control mode is off", body["error"])

    def test_cross_site_post_refused(self):
        self.assertEqual(self.req("POST", "/api/control/stop", {},
                                  headers={"X-M4-Request": "0"})[0], 403)
        self.assertEqual(self.req("POST", "/api/control/stop", {},
                                  headers={"Origin": "http://evil.example"})[0], 403)


class TestControlApi(ApiTestBase):
    def make_controller(self):
        script = os.path.join(tempfile.gettempdir(), "m4_mock_runner_%d.py" % os.getpid())
        with open(script, "w") as f:
            f.write(MOCK_RUNNER)
        self.mock_script = script
        return control.ExperimentControl(command_prefix=[sys.executable, script],
                                         log_dir=os.path.join(tempfile.gettempdir(), "m4_mock_logs"))

    def tearDown(self):
        ctl = self.httpd.RequestHandlerClass.controller
        if ctl.status()["running"]:
            ctl.stop()
            ctl.proc.wait(5)
        super().tearDown()
        os.unlink(self.mock_script)

    def test_validation(self):
        for body, msg in [({"scenario": "ddos"}, "must be one of"), ({}, "required"),
                          ({"scenario": "normal", "rm": "-rf"}, "unknown field"),
                          ({"scenario": "normal", "detector": "ml"}, "must be one of")]:
            status, r = self.req("POST", "/api/control/start", body)
            self.assertEqual(status, 400, body)
            self.assertIn(msg, r["error"])
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", "/api/control/start", body="not json",
                  headers={"Host": "127.0.0.1:%d" % self.port, "X-M4-Request": "1",
                           "Content-Type": "application/json"})
        self.assertEqual(c.getresponse().status, 400)
        c.close()

    def test_start_conflict_stop(self):
        status, st = self.req("POST", "/api/control/start",
                              {"scenario": "adaptive_ddos", "level": "subtle", "detector": "cusum"})
        self.assertEqual(status, 202)
        self.assertTrue(st["running"])
        self.assertEqual(st["params"], {"scenario": "adaptive_ddos", "level": "subtle",
                                        "detector": "cusum", "mitigation": "on"})
        self.assertEqual(self.req("POST", "/api/control/start", {"scenario": "normal"})[0], 409)
        self.assertEqual(self.req("POST", "/api/control/cleanup", {})[0], 409)
        time.sleep(0.5)
        status, st = self.req("GET", "/api/control")
        self.assertIn("--level', 'subtle'", " ".join(st["log_tail"]))
        self.assertEqual(self.req("POST", "/api/control/stop", {})[0], 202)
        deadline = time.time() + 5
        while self.req("GET", "/api/control")[1]["running"] and time.time() < deadline:
            time.sleep(0.1)
        st = self.req("GET", "/api/control")[1]
        self.assertFalse(st["running"])
        self.assertEqual(st["last_exit_code"], 130)
        self.assertTrue(st["stop_requested"])
        self.assertIn("got Ctrl+C", " ".join(st["log_tail"]))
        self.assertEqual(self.req("POST", "/api/control/stop", {})[0], 409)

    def test_non_adaptive_ignores_level(self):
        args, clean = control.validate({"scenario": "naive_ddos", "level": "aggressive"})
        self.assertNotIn("--level", args)
        self.assertNotIn("level", clean)


if __name__ == "__main__":
    unittest.main()

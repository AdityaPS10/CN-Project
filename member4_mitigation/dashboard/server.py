#!/usr/bin/env python3
"""Member 4 - live demo dashboard server (Python standard library only).

Read-only mode (default; no root needed):
    python3 member4_mitigation/dashboard/server.py            # http://127.0.0.1:8050/

Control mode (adds Start / Stop / Cleanup buttons; needs root like Mininet):
    sudo python3 member4_mitigation/dashboard/server.py --control

Read-only mode only READS the files experiments already write (state.py);
it never imports the controller or talks to the switch. Control mode
additionally launches the existing run_experiment.py (control.py) with
arguments from fixed lists, one experiment at a time, in its own process
session, so stopping or killing this server never stops a running
experiment. It listens on localhost only.

API (JSON):
    GET  /api/health              server status, mode, number of runs
    GET  /api/runs                run folders, newest first
    GET  /api/state?run=<id>      live/replay snapshot of one run (newest if omitted)
    GET  /api/summary             recorded results of all runs + offline detection replay
    GET  /api/control             experiment-control status (control mode)
    POST /api/control/start       {"scenario", "level", "detector", "mitigation"}
    POST /api/control/stop
    POST /api/control/cleanup     runs `mn -c` (refused while an experiment runs)
POST requests must come from this page: header X-M4-Request: 1, JSON body,
Host/Origin = this server (blocks cross-site requests and DNS rebinding).
"""
import argparse
import csv
import errno
import glob
import json
import os
import sys
import time
import traceback
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
if os.geteuid() == 0:
    sys.dont_write_bytecode = True      # no root-owned __pycache__ in the repository
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import state  # noqa: E402
import control  # noqa: E402

DEFAULT_RESULTS = os.path.normpath(os.path.join(HERE, "..", "results"))
DEFAULT_DECISIONS = os.path.join(HERE, "..", "..", "detection", "data", "decisions_live.csv")
MAX_BODY = 4096


def summary(results_dir):
    """Key metrics of every recorded run (from metrics.json) + offline detection rows."""
    from member4_mitigation import compare
    runs = []
    for m in compare.load(results_dir):
        row = {}
        for name, fn in compare.COLUMNS:
            try:
                row[name] = fn(m)
            except (KeyError, TypeError):
                row[name] = None
        runs.append(row)
    offline = []
    path = os.path.join(results_dir, "offline_detection.csv")
    if os.path.exists(path):
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                for k in ("tp", "fp", "fn", "tn"):
                    r[k] = int(r[k])
                r["detection_latency_s"] = float(r["detection_latency_s"]) if r["detection_latency_s"] else None
                offline.append(r)
    return {"runs": runs, "offline_detection": offline,
            "offline_available": bool(offline), "generated_at": time.time()}


class Handler(BaseHTTPRequestHandler):
    server_version = "M4Dashboard/2.0"
    results_dir = DEFAULT_RESULTS
    fixed_run_dir = None          # --run-dir
    controller = None             # control.ExperimentControl in control mode

    def log_message(self, fmt, *args):    # keep the terminal quiet; errors are printed below
        pass

    # ------------------------------------------------------------ helpers
    def _send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in ("127.0.0.1:%d" % port, "localhost:%d" % port)

    def _guard(self, handler):
        try:
            handler()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except control.ControlError as e:
            self._json(e.status, {"error": str(e)})
        except Exception as e:                     # noqa: BLE001 - report, never die
            traceback.print_exc()
            try:
                self._json(500, {"error": "internal error: %s" % e})
            except OSError:
                pass

    # ------------------------------------------------------------ GET
    def do_GET(self):
        self._guard(self._get)

    def _get(self):
        if not self._host_ok():
            return self._json(403, {"error": "unexpected Host header"})
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if url.path == "/api/health":
            return self._json(200, {"ok": True, "control_enabled": self.controller is not None,
                                    "fixed_run_dir": self.fixed_run_dir,
                                    "results_dir": self.results_dir,
                                    "runs": len(state.list_runs(self.results_dir)),
                                    "time": time.time()})
        if url.path == "/api/runs":
            return self._json(200, {"runs": state.list_runs(self.results_dir),
                                    "fixed": self.fixed_run_dir is not None})
        if url.path == "/api/state":
            return self._json(200, self._state(q.get("run", [""])[0]))
        if url.path == "/api/summary":
            return self._json(200, summary(self.results_dir))
        if url.path == "/api/control":
            if self.controller is None:
                return self._json(200, {"enabled": False, "choices": control.CHOICES})
            st = self.controller.status()
            st.update({"enabled": True, "choices": control.CHOICES})
            return self._json(200, st)
        return self._json(404, {"error": "not found"})

    def _state(self, run_id):
        if self.fixed_run_dir:
            return state.build_state(self.fixed_run_dir, DEFAULT_DECISIONS)
        run_dir = state.safe_run_dir(self.results_dir, run_id) if run_id else None
        if run_id and run_dir is None:
            return {"error": "unknown run %r" % run_id}
        if run_dir is None:
            runs = state.list_runs(self.results_dir)
            if not runs:
                return {"error": "no runs yet in %s - start an experiment and this page "
                                 "will follow it" % self.results_dir}
            run_dir = os.path.join(self.results_dir, runs[0]["id"])
        return state.build_state(run_dir)

    # ------------------------------------------------------------ POST
    def do_POST(self):
        self._guard(self._post)

    def _post(self):
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        if not self._host_ok() or self.headers.get("X-M4-Request") != "1" or \
                (origin and origin not in ("http://127.0.0.1:%d" % port, "http://localhost:%d" % port)):
            return self._json(403, {"error": "requests must come from the dashboard page"})
        if self.controller is None:
            return self._json(403, {"error": "control mode is off: start the server with "
                                             "'sudo python3 member4_mitigation/dashboard/server.py --control'"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._json(413, {"error": "request too large"})
        raw = self.rfile.read(length) if length else b"{}"
        if length and "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._json(415, {"error": "Content-Type must be application/json"})
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self._json(400, {"error": "body is not valid JSON"})
        path = urlparse(self.path).path
        if path == "/api/control/start":
            return self._json(202, self.controller.start(body))
        if path == "/api/control/stop":
            return self._json(202, self.controller.stop())
        if path == "/api/control/cleanup":
            return self._json(200, self.controller.cleanup())
        return self._json(404, {"error": "not found"})


def make_server(host, port, results_dir=DEFAULT_RESULTS, run_dir=None, controller=None):
    handler = type("BoundHandler", (Handler,), {
        "results_dir": os.path.abspath(results_dir),
        "fixed_run_dir": os.path.abspath(run_dir) if run_dir else None,
        "controller": controller})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="interface (keep localhost)")
    ap.add_argument("--port", type=int, default=8050)
    ap.add_argument("--run-dir", default=None,
                    help="show this folder only (e.g. member4_mitigation/logs for a manual session)")
    ap.add_argument("--control", action="store_true",
                    help="enable Start/Stop/Cleanup of experiments (requires sudo)")
    args = ap.parse_args()

    ctl = None
    if args.control:
        if os.geteuid() != 0:
            sys.exit("--control launches Mininet experiments and needs root: "
                     "sudo python3 member4_mitigation/dashboard/server.py --control")
        if not os.environ.get("SUDO_USER"):
            sys.exit("--control must be started with sudo from your normal account "
                     "(results are written as that user)")
        ctl = control.ExperimentControl()
    try:
        httpd = make_server(args.host, args.port, run_dir=args.run_dir, controller=ctl)
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            sys.exit("Port %d is already in use - a dashboard is probably already running: open "
                     "http://%s:%d/ (or stop it with Ctrl+C in its terminal, or use --port)"
                     % (args.port, args.host, args.port))
        raise
    print("Member 4 dashboard: http://%s:%d/  (%s; Ctrl+C to stop)" % (
        args.host, args.port, "CONTROL mode: can start experiments" if ctl else "read-only"),
        flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if ctl and ctl.status()["running"]:
            print("note: the running experiment continues; it stops by itself when finished",
                  flush=True)
        print("dashboard stopped", flush=True)


if __name__ == "__main__":
    main()

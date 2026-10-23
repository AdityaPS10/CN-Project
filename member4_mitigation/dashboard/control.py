"""Member 4 dashboard - optional experiment control (start / stop / cleanup).

Only used when server.py is started with --control (which requires root,
because Mininet does). It launches the EXISTING runner,
member4_mitigation/run_experiment.py, as a child process with arguments
taken only from the fixed choices below - never free text - and allows one
experiment at a time.

Isolation: the runner gets its own process session, so stopping or killing
the dashboard server does not stop a running experiment. "Stop" sends SIGINT
(Ctrl+C) to the runner, whose own cleanup then stops traffic, Mininet, the
detector and the controller exactly as when Ctrl+C is pressed in a terminal.
"""
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RUNNER = os.path.join(ROOT, "member4_mitigation", "run_experiment.py")
LOG_DIR = os.path.join(ROOT, "member4_mitigation", "logs")

CHOICES = {
    "scenario": ["normal", "flash_crowd", "naive_ddos", "adaptive_ddos"],
    "level": ["subtle", "moderate", "aggressive"],
    "detector": ["combined", "threshold", "cusum", "entropy"],
    "mitigation": ["on", "off"],
}


class ControlError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def validate(params):
    """Return the runner arguments for a request body, or raise ControlError(400)."""
    if not isinstance(params, dict):
        raise ControlError(400, "body must be a JSON object")
    unknown = set(params) - set(CHOICES)
    if unknown:
        raise ControlError(400, "unknown field(s): %s" % ", ".join(sorted(unknown)))
    clean = {}
    for key, allowed in CHOICES.items():
        default = {"level": "moderate", "detector": "combined", "mitigation": "on"}.get(key)
        value = params.get(key, default)
        if value is None:
            raise ControlError(400, "'%s' is required" % key)
        if value not in allowed:
            raise ControlError(400, "'%s' must be one of %s" % (key, ", ".join(allowed)))
        clean[key] = value
    args = ["--scenario", clean["scenario"], "--detector", clean["detector"],
            "--mitigation", clean["mitigation"], "--tag", "ui"]
    if clean["scenario"] == "adaptive_ddos":
        args += ["--level", clean["level"]]
    else:
        clean.pop("level")
    return args, clean


class ExperimentControl:
    def __init__(self, command_prefix=None, log_dir=LOG_DIR):
        # command_prefix is replaceable only so tests can use a stand-in runner.
        self.command_prefix = command_prefix or [sys.executable, RUNNER]
        self.log_dir = log_dir
        self.lock = threading.Lock()
        self.proc = None
        self.params = None
        self.started_at = None
        self.finished_at = None
        self.log_path = None
        self.last_exit = None
        self.stop_requested = False

    def _running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, body):
        args, clean = validate(body)
        with self.lock:
            if self._running():
                raise ControlError(409, "an experiment is already running; stop it first")
            os.makedirs(self.log_dir, exist_ok=True)
            self.log_path = os.path.join(self.log_dir, "ui_run_%s.log" % time.strftime("%Y%m%d_%H%M%S"))
            log = open(self.log_path, "w")
            try:
                self.proc = subprocess.Popen(self.command_prefix + args, cwd=ROOT, stdout=log,
                                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                             start_new_session=True)
            except OSError as e:
                raise ControlError(500, "could not start the runner: %s" % e)
            finally:
                log.close()
            self.params, self.started_at = clean, time.time()
            self.finished_at, self.last_exit, self.stop_requested = None, None, False
            return self.status()

    def stop(self):
        with self.lock:
            if not self._running():
                raise ControlError(409, "no experiment is running")
            self.stop_requested = True
            try:
                os.killpg(self.proc.pid, signal.SIGINT)     # like Ctrl+C in a terminal
            except ProcessLookupError:
                pass
            return self.status()

    def cleanup(self):
        """`mn -c`: remove leftover Mininet state after a crash. Refused while running."""
        with self.lock:
            if self._running():
                raise ControlError(409, "an experiment is running; stop it first")
            r = subprocess.run(["mn", "-c"], capture_output=True, text=True, timeout=120)
            return {"ok": r.returncode == 0, "exit_code": r.returncode,
                    "output_tail": (r.stdout + r.stderr).splitlines()[-6:]}

    def status(self):
        running = self._running()
        if self.proc is not None and not running and self.last_exit is None:
            self.last_exit = self.proc.returncode
            self.finished_at = time.time()
        tail = []
        if self.log_path and os.path.exists(self.log_path):
            try:
                with open(self.log_path, errors="replace") as f:
                    tail = list(deque(f, maxlen=14))
            except OSError:
                tail = []
        return {"running": running, "pid": self.proc.pid if self.proc else None,
                "params": self.params, "started_at": self.started_at,
                "elapsed_s": (time.time() if running else (self.finished_at or time.time()))
                - self.started_at if self.started_at else None,
                "last_exit_code": self.last_exit, "stop_requested": self.stop_requested,
                "log_path": self.log_path, "log_tail": [line.rstrip("\n") for line in tail]}

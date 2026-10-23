#!/usr/bin/env python3
"""Member 4 - runs ONE complete, labelled experiment and evaluates it.

    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos
    sudo python3 member4_mitigation/run_experiment.py --scenario adaptive_ddos --level subtle
    sudo python3 member4_mitigation/run_experiment.py --scenario flash_crowd --mitigation off
    sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos --detector cusum

What happens (all times recorded in meta.json):
  1. controller (Member 1 switch + Member 2 monitor + our app) and the
     detector (Member 3 combined, or a baseline) start as the normal user;
  2. Mininet topology identical to topo/basic_topo.py (1 switch, h1..h6);
  3. after --warmup s: measuring sink on h1, LEGITIMATE background client on
     h6 (Member 1's normal_traffic.py, 10 pkt/s) and a ping h6 -> h1;
  4. after --lead s: the scenario's traffic on its hosts, using Member 1's
     generators with the same settings as the recorded runs;
  5. --cooldown s after the scenario ends (to observe release), everything
     stops, Member 2's features.csv is moved into the run folder, and
     evaluator.py writes metrics.json.

Results: member4_mitigation/results/<time>_<scenario>[_<level>]_<detector>_mit-<on|off>/
"""
import argparse
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TG = os.path.join(ROOT, "trafficgen")
FEATURES = os.path.join(ROOT, "sdn-ddos-monitoring", "data", "features.csv")

# Hosts per scenario and Member 1 generator settings, matching the runs
# recorded in sdn-ddos-monitoring/validation/ (see member4_mitigation/README.md).
SCENARIOS = {
    "normal":        {"hosts": ["h2", "h3"],             "attack": False},
    "flash_crowd":   {"hosts": ["h2", "h3", "h4"],       "attack": False},
    "naive_ddos":    {"hosts": ["h2", "h3", "h4", "h5"], "attack": True},
    "adaptive_ddos": {"hosts": ["h2", "h3", "h4", "h5"], "attack": True},
}
LEGIT_BG_HOST = "h6"
LEGIT_BG_RATE = 10
SERVER = "h1"
SERVER_IP = "10.0.0.1"


def scenario_cmd(scenario, host, log, level, start_at):
    common = ["--src-name=%s" % host, "--dst-name=h1", "--dst-ip=%s" % SERVER_IP,
              "--log=%s" % log]
    if scenario == "normal":
        return ["python3", os.path.join(TG, "normal_traffic.py")] + common + [
            "--rate=10", "--duration=30"]
    if scenario == "flash_crowd":
        return ["python3", os.path.join(TG, "flash_crowd_traffic.py")] + common + [
            "--num-flows=5", "--ramp-up=10", "--hold=12", "--rate-min=5", "--rate-max=15"]
    if scenario == "naive_ddos":
        return ["python3", os.path.join(TG, "naive_ddos_traffic.py")] + common + [
            "--rate=100", "--duration=20"]
    if scenario == "adaptive_ddos":
        return ["python3", os.path.join(TG, "adaptive_ddos_traffic.py")] + common + [
            "--duration=40", "--attack-level=%s" % level, "--start-at=%.3f" % start_at]
    raise ValueError(scenario)


def say(msg):
    print("[run_experiment %s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def port_listening(port):
    """True if something listens on TCP `port` (reads /proc, no connection made)."""
    want = ":%04X" % port
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if parts[1].endswith(want) and parts[3] == "0A":
                        return True
        except OSError:
            pass
    return False


def stop_process(p, name, grace=4.0):
    if p is None or p.poll() is not None:
        return
    for sig, wait in ((signal.SIGINT, grace), (signal.SIGINT, 2.0), (signal.SIGKILL, 2.0)):
        try:
            p.send_signal(sig)
            p.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue
        except ProcessLookupError:
            return
    say("warning: %s (pid %s) did not stop" % (name, p.pid))


def chown_tree(path, uid, gid):
    for dirpath, dirnames, filenames in os.walk(path):
        os.chown(dirpath, uid, gid)
        for n in filenames:
            os.chown(os.path.join(dirpath, n), uid, gid)


class OvsSampler(threading.Thread):
    """Reads the switch's OWN view every second with ovs-ofctl (root), as an
    independent check that our rules really exist on the switch:
      m4_flows   flows carrying our cookie 0x4d34
      meters     meters configured
      meter_packets_in / meter_packets_dropped
                 sums over meters of packets that reached a meter / that its
                 drop band discarded (cumulative per meter; reset when the
                 meter is deleted at release)."""
    BAND = re.compile(r"\b\d+: packet_count:(\d+)")
    PIN = re.compile(r"packet_in_count:(\d+)")

    def __init__(self, bridge, out_path, interval=1.0):
        super().__init__(daemon=True)
        self.bridge, self.out_path, self.interval = bridge, out_path, interval
        self.halt = threading.Event()

    def _ofctl(self, *args):
        r = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13"] + list(args) + [self.bridge],
                           capture_output=True, text=True, timeout=5)
        return r.stdout if r.returncode == 0 else None

    def run(self):
        with open(self.out_path, "w") as fh:
            fh.write("wall_time,m4_flows,meters,meter_packets_in,meter_packets_dropped\n")
            while not self.halt.wait(self.interval):
                try:
                    flows = self._ofctl("dump-flows")
                    meters = self._ofctl("dump-meters")
                    stats = self._ofctl("meter-stats")
                except (OSError, subprocess.SubprocessError):
                    continue
                if flows is None or meters is None or stats is None:
                    continue          # bridge not there (yet / any more)
                m4 = sum("cookie=0x4d34" in line for line in flows.splitlines())
                n_meters = sum(line.startswith("meter=") for line in meters.splitlines())
                pin = sum(int(x) for x in self.PIN.findall(stats))
                drop = sum(int(x) for x in self.BAND.findall(stats))
                fh.write("%.3f,%d,%d,%d,%d\n" % (time.time(), m4, n_meters, pin, drop))
                fh.flush()

    def stop(self):
        self.halt.set()
        self.join(timeout=10)


def write_meta(run_dir, meta, uid, gid):
    """(Re)write meta.json atomically, so a reader (the dashboard) never sees
    a half-written file. Called when the network is up, at each phase, and
    at the end."""
    path = os.path.join(run_dir, "meta.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=2)
    os.chown(tmp, uid, gid)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--level", default="moderate", choices=["subtle", "moderate", "aggressive"],
                    help="adaptive_ddos attack level (ignored for other scenarios)")
    ap.add_argument("--detector", default="combined",
                    choices=["combined", "threshold", "cusum", "entropy"])
    ap.add_argument("--mitigation", default="on", choices=["on", "off"])
    ap.add_argument("--set", action="append", default=[], metavar="NAME=VALUE",
                    help="override a member4_mitigation/config.py setting for this run")
    ap.add_argument("--warmup", type=float, default=10.0)
    ap.add_argument("--lead", type=float, default=15.0)
    ap.add_argument("--cooldown", type=float, default=25.0)
    ap.add_argument("--tag", default="")
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--venv-python", default=None,
                    help="python with os-ken (default ~USER/ryu-venv/bin/python)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Mininet needs root: run with sudo")
    # Traffic generators and the sink run as root inside Mininet hosts; stop them
    # leaving root-owned __pycache__ folders in the repository.
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    if not args.user or args.user == "root":
        sys.exit("run via sudo from your normal account (or pass --user NAME)")
    pw = pwd.getpwnam(args.user)
    venv_python = args.venv_python or os.path.join(pw.pw_dir, "ryu-venv", "bin", "python")
    if not os.path.exists(venv_python):
        sys.exit("os-ken python not found at %s (use --venv-python)" % venv_python)
    if port_listening(6653):
        sys.exit("port 6653 is already in use: stop the other controller first "
                 "(ss -ltnp | grep 6653)")

    overrides = {}
    for item in args.set:
        name, _, value = item.partition("=")
        if not name or not value:
            sys.exit("--set needs NAME=VALUE, got %r" % item)
        overrides[name.strip().upper()] = value.strip()

    level = args.level if args.scenario == "adaptive_ddos" else None
    run_id = "_".join(x for x in [time.strftime("%Y%m%d_%H%M%S"), args.scenario, level,
                                  args.detector, "mit-" + args.mitigation, args.tag] if x)
    run_dir = os.path.join(HERE, "results", run_id)
    traffic_dir = os.path.join(run_dir, "traffic")
    os.makedirs(traffic_dir)
    chown_tree(os.path.join(HERE, "results"), pw.pw_uid, pw.pw_gid)
    say("run folder: %s" % run_dir)

    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    user_env = {"HOME": pw.pw_dir, "USER": args.user, "LOGNAME": args.user,
                "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PYTHONPATH": "%s:%s" % (ROOT, os.path.join(ROOT, "sdn-ddos-monitoring")),
                "PYTHONUNBUFFERED": "1",
                "M4_RUN_DIR": run_dir,
                "M4_DECISIONS": os.path.join(run_dir, "decisions.csv"),
                "M4_MITIGATION": args.mitigation}
    for k, v in overrides.items():
        user_env["M4_" + k] = v
    as_user = dict(user=pw.pw_uid, group=pw.pw_gid, extra_groups=[], env=user_env)

    meta = {"run_id": run_id, "scenario": args.scenario, "attack_level": level,
            "detector": args.detector, "mitigation": args.mitigation,
            "config_overrides": overrides, "tag": args.tag,
            "attack_hosts": SCENARIOS[args.scenario]["hosts"] if SCENARIOS[args.scenario]["attack"] else [],
            "legit_hosts": ([] if SCENARIOS[args.scenario]["attack"] else SCENARIOS[args.scenario]["hosts"])
                           + [LEGIT_BG_HOST],
            "scenario_hosts": SCENARIOS[args.scenario]["hosts"],
            "server": SERVER, "legit_bg_host": LEGIT_BG_HOST, "legit_bg_rate_pps": LEGIT_BG_RATE,
            "warmup_s": args.warmup, "lead_s": args.lead, "cooldown_s": args.cooldown,
            "t_run_start": time.time(), "status": "starting"}
    try:
        meta["git_commit"] = subprocess.run(
            ["git", "-c", "safe.directory=" + ROOT, "-C", ROOT, "rev-parse", "HEAD"],
            capture_output=True, text=True).stdout.strip()
    except OSError:
        pass

    ctl = det = net = mon = sink = bg = ping = ovs = None
    scen_procs = []
    open_files = []
    try:
        # 1. controller + detector, as the normal user
        ctl_log = open(os.path.join(run_dir, "controller.log"), "w")
        open_files.append(ctl_log)
        ctl = subprocess.Popen([venv_python, os.path.join(ROOT, "tools", "osken_run.py"),
                                "controller.simple_switch_13", "monitor",
                                "member4_mitigation.mitigation_app"],
                               cwd=ROOT, stdout=ctl_log, stderr=subprocess.STDOUT, **as_user)
        deadline = time.time() + 20
        while not port_listening(6653):
            if ctl.poll() is not None or time.time() > deadline:
                raise RuntimeError("controller did not start; see %s/controller.log" % run_dir)
            time.sleep(0.2)
        say("controller up (pid %d)" % ctl.pid)

        det_log = open(os.path.join(run_dir, "detector.log"), "w")
        open_files.append(det_log)
        decisions = os.path.join(run_dir, "decisions.csv")
        if args.detector == "combined":
            det_cmd, det_cwd = ["python3", "live_detector.py", "--output", decisions], \
                os.path.join(ROOT, "detection")
        else:
            det_cmd, det_cwd = ["python3", "-m", "member4_mitigation.baseline_detectors",
                                "--mode", args.detector, "--output", decisions], ROOT
        det = subprocess.Popen(det_cmd, cwd=det_cwd, stdout=det_log,
                               stderr=subprocess.STDOUT, **as_user)
        say("detector '%s' up (pid %d)" % (args.detector, det.pid))

        from member4_mitigation.resource_monitor import ResourceMonitor
        mon = ResourceMonitor({"controller": ctl.pid, "detector": det.pid},
                              os.path.join(run_dir, "resources.csv"))
        mon.start()

        # 2. topology (same as topo/basic_topo.py)
        from mininet.net import Mininet
        from mininet.node import RemoteController, OVSSwitch
        from mininet.link import TCLink
        from mininet.log import setLogLevel
        setLogLevel("warning")
        net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
        s1 = net.addSwitch("s1", protocols="OpenFlow13")
        for i in range(1, 7):
            net.addLink(net.addHost("h%d" % i, ip="10.0.0.%d/24" % i), s1)
        net.start()
        if not net.waitConnected(timeout=20):
            raise RuntimeError("switch did not connect to the controller")
        meta["port_map"] = {}
        meta["host_ips"] = {}
        for h in net.hosts:
            sw_intf = h.connectionsTo(s1)[0][1]
            meta["port_map"][str(s1.ports[sw_intf])] = h.name
            meta["host_ips"][h.name] = h.IP()
        say("network up, switch connected; port map %s" % meta["port_map"])
        ovs = OvsSampler("s1", os.path.join(run_dir, "ovs.csv"))
        ovs.start()
        meta["status"] = "running"
        write_meta(run_dir, meta, pw.pw_uid, pw.pw_gid)

        say("warm-up %.0fs" % args.warmup)
        time.sleep(args.warmup)

        # 3. measuring sink, legitimate background client, ping
        h = {x.name: x for x in net.hosts}
        sink_log = open(os.path.join(run_dir, "sink.log"), "w")
        open_files.append(sink_log)
        sink = h[SERVER].popen(["python3", os.path.join(HERE, "sink.py"), "--port=5000",
                                "--out=%s" % os.path.join(run_dir, "sink.csv")],
                               stdout=sink_log, stderr=subprocess.STDOUT)
        time.sleep(1.0)
        scen_dur = {"normal": 30, "flash_crowd": 22, "naive_ddos": 20, "adaptive_ddos": 43}
        bg_dur = args.lead + scen_dur[args.scenario] + args.cooldown
        meta["t_bg_start"] = time.time()
        write_meta(run_dir, meta, pw.pw_uid, pw.pw_gid)
        bg_out = open(os.path.join(traffic_dir, "legit_%s.out" % LEGIT_BG_HOST), "w")
        open_files.append(bg_out)
        bg = h[LEGIT_BG_HOST].popen(
            ["python3", os.path.join(TG, "normal_traffic.py"), "--src-name=%s" % LEGIT_BG_HOST,
             "--dst-name=h1", "--dst-ip=%s" % SERVER_IP, "--rate=%d" % LEGIT_BG_RATE,
             "--duration=%.0f" % bg_dur,
             "--log=%s" % os.path.join(traffic_dir, "legit_%s.csv" % LEGIT_BG_HOST)],
            stdout=bg_out, stderr=subprocess.STDOUT)
        ping_out = open(os.path.join(run_dir, "ping_%s.txt" % LEGIT_BG_HOST), "w")
        open_files.append(ping_out)
        ping = h[LEGIT_BG_HOST].popen(["ping", "-D", "-i", "0.5", "-w", "%.0f" % bg_dur,
                                       SERVER_IP], stdout=ping_out, stderr=subprocess.STDOUT)
        say("sink, legitimate client %s (%d pkt/s) and ping started; scenario in %.0fs"
            % (LEGIT_BG_HOST, LEGIT_BG_RATE, args.lead))
        time.sleep(args.lead)

        # 4. scenario traffic (Member 1's generators)
        start_at = time.time() + 3
        meta["t_scenario_start"] = time.time()
        write_meta(run_dir, meta, pw.pw_uid, pw.pw_gid)
        for host in SCENARIOS[args.scenario]["hosts"]:
            log = os.path.join(traffic_dir, "%s_%s.csv" % (args.scenario, host))
            out = open(log[:-4] + ".out", "w")
            open_files.append(out)
            scen_procs.append(h[host].popen(scenario_cmd(args.scenario, host, log, args.level,
                                                         start_at),
                                            stdout=out, stderr=subprocess.STDOUT))
        say("scenario '%s'%s running on %s" % (args.scenario, " (%s)" % level if level else "",
                                               ", ".join(SCENARIOS[args.scenario]["hosts"])))
        for p in scen_procs:
            p.wait(timeout=scen_dur[args.scenario] + 60)
        meta["t_scenario_end"] = time.time()
        write_meta(run_dir, meta, pw.pw_uid, pw.pw_gid)
        say("scenario finished; cool-down %.0fs" % args.cooldown)
        time.sleep(args.cooldown)
        meta["t_stop"] = time.time()
    finally:
        for p, name in [(ping, "ping"), (bg, "legit client"), (sink, "sink")] + \
                       [(p, "scenario") for p in scen_procs]:
            stop_process(p, name, grace=3.0)
        if ovs is not None:
            ovs.stop()
        if net is not None:
            net.stop()
        if mon is not None:
            mon.stop()
        stop_process(det, "detector")
        stop_process(ctl, "controller")
        for f in open_files:
            f.close()
        meta["t_run_end"] = time.time()
        if os.path.exists(FEATURES):
            shutil.move(FEATURES, os.path.join(run_dir, "features.csv"))
        meta["status"] = "finished" if "t_stop" in meta else "aborted"
        write_meta(run_dir, meta, pw.pw_uid, pw.pw_gid)
        chown_tree(run_dir, pw.pw_uid, pw.pw_gid)

    say("evaluating ...")
    try:
        from member4_mitigation import evaluator
        metrics = evaluator.evaluate_run(run_dir)
        evaluator.write_metrics(run_dir, metrics)
        chown_tree(run_dir, pw.pw_uid, pw.pw_gid)
        print(evaluator.format_summary(metrics))
    except Exception as e:
        say("evaluation failed (%s); data is kept, rerun: "
            "python3 -m member4_mitigation.evaluator %s" % (e, run_dir))
        raise
    say("done: %s" % run_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl+C or the dashboard's Stop button: main()'s finally block has already
        # stopped traffic, Mininet, detector and controller and marked the run 'aborted'.
        say("stopped by user (Ctrl+C); cleanup done, run marked 'aborted' and not evaluated")
        sys.exit(130)

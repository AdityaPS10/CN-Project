"""Member 4 - os-ken controller app: Member 3's live decisions -> mitigation.

Runs alongside Member 1's switch and Member 2's monitor in ONE controller
process, without modifying either of them:

    PYTHONPATH=$PWD:$PWD/sdn-ddos-monitoring ~/ryu-venv/bin/python \\
        tools/osken_run.py controller.simple_switch_13 monitor \\
        member4_mitigation.mitigation_app

Every POLL_INTERVAL it reads new decisions, runs the policy (mitigation.py)
and, while mitigation is on, meters the ports that rate_limiter.py picks as
offenders (flow_rules.py). When the policy stops, all our rules and meters
are removed. With MITIGATION_ENABLED=False it only logs (baseline mode).

Logs written to config.RUN_DIR (rewritten at each start):
    actions.csv     one row per decision: the policy's action
    events.csv      switch connects, rules sent/confirmed/removed, errors
    port_stats.csv  per-port received packets and rate, every poll
"""
import csv
import os
import threading
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub

from member4_mitigation import config, flow_rules
from member4_mitigation.decisions import DecisionFollower
from member4_mitigation.mitigation import MitigationPolicy
from member4_mitigation.rate_limiter import PortRateTracker


class _CsvLog:
    def __init__(self, path, columns):
        self._fh = open(path, "w", newline="")
        self._w = csv.writer(self._fh, lineterminator="\n")
        self._w.writerow(columns)
        self._fh.flush()

    def write(self, values):
        self._w.writerow(values)
        self._fh.flush()


class MitigationApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MitigationApp, self).__init__(*args, **kwargs)
        self.lock = threading.Lock()     # event handlers and our threads share state
        self.datapaths = {}              # dpid -> datapath
        self.limited = {}                # dpid -> {port: meter_id}
        self.pending = {}                # barrier xid -> (kind, dpid, ports, t_sent, t_decision)
        self.policy = MitigationPolicy()
        self.feed = DecisionFollower(config.DECISIONS_PATH)
        self.tracker = PortRateTracker(config.OFFENDER_MIN_PPS, config.OFFENDER_LOOKBACK_S,
                                       config.MAX_LIMITED_PORTS, config.PROTECTED_PORTS)

        os.makedirs(config.RUN_DIR, exist_ok=True)
        self.actions_log = _CsvLog(os.path.join(config.RUN_DIR, "actions.csv"),
                                   ["wall_time", "decision_timestamp", "traffic_class", "rule",
                                    "score", "action", "mitigation_active", "why"])
        self.events_log = _CsvLog(os.path.join(config.RUN_DIR, "events.csv"),
                                  ["wall_time", "event", "dpid", "ports", "detail"])
        self.ports_log = _CsvLog(os.path.join(config.RUN_DIR, "port_stats.csv"),
                                 ["wall_time", "dpid", "port", "rx_packets", "rx_pps"])

        self.logger.info("[M4] following %s", os.path.abspath(config.DECISIONS_PATH))
        self.logger.info("[M4] logs in %s, enforcement %s",
                         os.path.abspath(config.RUN_DIR),
                         "ON" if config.MITIGATION_ENABLED else "OFF (monitor only)")
        self._event("app_started", None, [], "enforcement=%s meter_rate_pps=%s offender_min_pps=%s"
                    % (config.MITIGATION_ENABLED, config.METER_RATE_PPS, config.OFFENDER_MIN_PPS))
        self.decision_thread = hub.spawn(self._decision_loop)
        self.stats_thread = hub.spawn(self._stats_loop)

    # ---------------------------------------------------------------- logging
    def _event(self, event, dpid, ports, detail=""):
        self.events_log.write(["%.3f" % time.time(), event,
                               "" if dpid is None else "%016x" % dpid,
                               " ".join(str(p) for p in ports), detail])

    # --------------------------------------------------------- switch events
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        with self.lock:
            if ev.state == MAIN_DISPATCHER:
                self.datapaths[dp.id] = dp
                self.limited[dp.id] = {}
                self.logger.info("[M4] switch connected dpid=%016x", dp.id)
                self._event("switch_connected", dp.id, [])
                if config.MITIGATION_ENABLED:
                    # Recovery: clear anything we left on the switch last time.
                    flow_rules.remove_all(dp, config.COOKIE)
                    xid = flow_rules.barrier(dp)
                    self.pending[xid] = ("cleanup", dp.id, [], time.time(), None)
            elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
                del self.datapaths[dp.id]
                self.limited.pop(dp.id, None)
                self.tracker.forget(dp.id)
                self.logger.info("[M4] switch disconnected dpid=%016x", dp.id)
                self._event("switch_disconnected", dp.id, [])

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        now = time.time()
        dp = ev.msg.datapath
        with self.lock:
            for st in ev.msg.body:
                if st.port_no > dp.ofproto.OFPP_MAX:
                    continue          # the switch's LOCAL port, not a host
                pps = self.tracker.update(dp.id, st.port_no, now, st.rx_packets)
                self.ports_log.write(["%.3f" % now, "%016x" % dp.id, st.port_no,
                                      st.rx_packets, "" if pps is None else "%.2f" % pps])

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        now = time.time()
        with self.lock:
            item = self.pending.pop(ev.msg.xid, None)
            if item is None:
                return
            kind, dpid, ports, t_sent, t_decision = item
            detail = "switch_ms=%.1f" % ((now - t_sent) * 1000)
            if t_decision is not None:
                detail += " decision_to_applied_ms=%.1f" % ((now - t_decision) * 1000)
            self._event(kind + "_confirmed", dpid, ports, detail)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_handler(self, ev):
        m = ev.msg
        with self.lock:
            self.logger.warning("[M4] switch error type=%s code=%s xid=%s", m.type, m.code, m.xid)
            self._event("of_error", m.datapath.id, [], "type=%s code=%s xid=%s"
                        % (m.type, m.code, m.xid))

    # ------------------------------------------------------------- threads
    def _stats_loop(self):
        while True:
            try:
                with self.lock:
                    dps = list(self.datapaths.values())
                for dp in dps:
                    flow_rules.request_port_stats(dp)
            except Exception:
                self.logger.exception("[M4] error requesting port stats")
            hub.sleep(config.PORT_STATS_INTERVAL)

    def _decision_loop(self):
        while True:
            try:
                self._poll_decisions()
            except Exception:
                # Never let one bad row kill the thread silently.
                self.logger.exception("[M4] error while handling decisions")
            hub.sleep(config.POLL_INTERVAL)

    def _poll_decisions(self):
        decisions, notes = self.feed.poll()
        with self.lock:
            for kind, msg in notes:
                self.logger.warning("[M4] %s", msg)
                self._event("input_" + kind, None, [], msg)
                if kind == "reset" and self.policy.reset():
                    self.logger.info("[M4] STOP mitigation (detector restarted)")
                    self._remove_all("detector_restarted")

            for d in decisions:
                now = time.time()
                a = self.policy.process(d)
                self.actions_log.write(["%.3f" % now, "%.3f" % d.timestamp, d.traffic_class,
                                        d.rule, d.score, a.action, int(self.policy.active),
                                        a.why])
                if a.action in ("start", "stop"):
                    self.logger.info("[M4] %s mitigation: class=%s rule=%s score=%s",
                                     a.action.upper(), d.traffic_class, d.rule, d.score)
                if not config.MITIGATION_ENABLED:
                    continue
                if self.policy.active:
                    self._limit_offenders(now, first=(a.action == "start"))
                elif a.action == "stop":
                    self._remove_all("policy_stop")

    # ---------------------------------------------------------- enforcement
    # (callers hold self.lock)
    def _limit_offenders(self, t_decision, first):
        now = time.time()
        for dpid, dp in self.datapaths.items():
            limited = self.limited.setdefault(dpid, {})
            new = []
            for port, peak in self.tracker.offenders(dpid, now):
                if port in limited or len(limited) >= config.MAX_LIMITED_PORTS:
                    continue
                limited[port] = flow_rules.install_rate_limit(
                    dp, port, config.METER_RATE_PPS, config.METER_BURST,
                    config.COOKIE, config.RULE_PRIORITY)
                new.append(port)
                self._event("limit_sent", dpid, [port], "peak_pps=%.1f meter_rate_pps=%s"
                            % (peak, config.METER_RATE_PPS))
            if new:
                xid = flow_rules.barrier(dp)
                self.pending[xid] = ("limit", dpid, new, now, t_decision)
                self.logger.info("[M4] rate-limiting port(s) %s to %s pkt/s",
                                 new, config.METER_RATE_PPS)
            elif first and not limited:
                self._event("no_offender_found", dpid, [],
                            "no port reached %s pkt/s in the last %ss"
                            % (config.OFFENDER_MIN_PPS, config.OFFENDER_LOOKBACK_S))

    def _remove_all(self, reason):
        now = time.time()
        for dpid, dp in self.datapaths.items():
            ports = sorted(self.limited.get(dpid, {}))
            if not ports:
                continue
            flow_rules.remove_all(dp, config.COOKIE)
            xid = flow_rules.barrier(dp)
            self.pending[xid] = ("remove", dpid, ports, now, None)
            self.limited[dpid] = {}
            self._event("remove_sent", dpid, ports, reason)
            self.logger.info("[M4] removed limits on port(s) %s (%s)", ports, reason)

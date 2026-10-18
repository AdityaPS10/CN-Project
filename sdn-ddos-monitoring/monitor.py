"""
Member 2 - Step 5: Packet-In rate + Flow Creation rate.
New flow = unseen (src_ip, dst_ip) pair (IPv4 or ARP) in a Packet-In.
"""
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ipv4, arp

import config
from features import shannon_entropy, iat_stats
from csv_logger import CsvLogger


class Monitor(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Monitor, self).__init__(*args, **kwargs)
        self.packet_in_count = 0
        self.new_flow_count = 0
        self.window_sources = []
        self.window_times = []
        self.prev_ts = None
        self.flow_last_seen = {}      # (src_ip, dst_ip) -> last time seen
        self.datapaths = {}
        self.controller_request_count = 0
        self.flow_table_occupancy = 0
        self.packet_count_total = 0
        self.packet_count_prev = None
        self.packet_count_seen = False
        self.window_index = 0
        self.csv = CsvLogger(config.CSV_PATH)
        self.window_thread = hub.spawn(self._window_loop)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        now = time.time()
        self.packet_in_count += 1
        self.controller_request_count += 1

        pkt = packet.Packet(ev.msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        a = pkt.get_protocol(arp.arp)
        if ip:
            key = (ip.src, ip.dst)
            self.window_sources.append(ip.src)
            self.window_times.append(now)
        elif a:
            key = (a.src_ip, a.dst_ip)
            self.window_sources.append(a.src_ip)
            self.window_times.append(now)
        else:
            return                    # IPv6 / other: not a flow for us

        last = self.flow_last_seen.get(key)
        if last is None or now - last > config.FLOW_IDLE_TIMEOUT:
            self.new_flow_count += 1
        self.flow_last_seen[key] = now

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        self.flow_table_occupancy = ev.msg.body.flow_count
        self.packet_count_total = ev.msg.body.packet_count
        self.packet_count_seen = True

    @set_ev_cls([ofp_event.EventOFPEchoRequest,
                 ofp_event.EventOFPPortStatus,
                 ofp_event.EventOFPFlowRemoved,
                 ofp_event.EventOFPErrorMsg], MAIN_DISPATCHER)
    def other_request_handler(self, ev):
        self.controller_request_count += 1

    def _request_flow_count(self):
        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            req = parser.OFPAggregateStatsRequest(
                dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                0, 0, parser.OFPMatch())
            dp.send_msg(req)

    def _window_loop(self):
        while not self.datapaths:
            hub.sleep(0.05)
        start = time.time()
        n = 0
        while True:
            n += 1
            deadline = start + n * config.WINDOW_SIZE
            delay = deadline - time.time()
            if delay > 0:
                hub.sleep(delay)
            ts = deadline
            self._request_flow_count()
            self.window_index += 1
            pin = self.packet_in_count
            new = self.new_flow_count
            creq = self.controller_request_count
            self.controller_request_count = 0
            self.packet_in_count = 0
            self.new_flow_count = 0
            if not self.packet_count_seen:
                dp_delta = 0
            elif self.packet_count_prev is None:
                dp_delta = 0
                self.packet_count_prev = self.packet_count_total
            else:
                dp_delta = max(0, self.packet_count_total - self.packet_count_prev)
                self.packet_count_prev = self.packet_count_total
            dp_rate = dp_delta / config.WINDOW_SIZE
            entropy = shannon_entropy(self.window_sources)
            self.window_sources = []
            mean_iat, min_iat, max_iat, jitter = iat_stats(self.window_times, self.prev_ts)
            if self.window_times:
                self.prev_ts = self.window_times[-1]
            self.window_times = []
            self.logger.info(
                "[WINDOW %d] t=%.3f PacketInCount=%d PacketInRate=%.2f "
                "NewFlows=%d FlowCreationRate=%.2f SourceIPEntropy=%.3f MeanIAT=%.4f MinIAT=%.4f MaxIAT=%.4f Jitter=%.4f FlowTableOccupancy=%d ControllerRequestRate=%.2f DataPlanePacketRate=%.2f",
                self.window_index, ts, pin, pin / config.WINDOW_SIZE,
                new, new / config.WINDOW_SIZE, entropy,
                mean_iat, min_iat, max_iat, jitter,
                self.flow_table_occupancy, creq / config.WINDOW_SIZE, dp_rate)
            vec = [
                "%.3f" % ts,
                "%.2f" % (pin / config.WINDOW_SIZE),
                "%.2f" % (new / config.WINDOW_SIZE),
                "%.4f" % entropy,
                "%.6f" % mean_iat,
                "%.6f" % jitter,
                "%d" % self.flow_table_occupancy,
                "%.2f" % (creq / config.WINDOW_SIZE),
                "",
                "%.2f" % dp_rate,
            ]
            self.logger.info("[VECTOR] " + ",".join(vec))
            self.csv.write_row(vec)

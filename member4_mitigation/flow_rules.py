"""Member 4 - OpenFlow 1.3 messages for mitigation (install / remove).

What one "rate limit" on switch port P consists of:
  1. a meter (id = P) with a single DROP band at METER_RATE_PPS packets/s
     (OVS 3.7 on this testbed reports: max_meter 200000, band type drop, pktps);
  2. a flow rule, priority RULE_PRIORITY, match in_port=P, cookie COOKIE:
       instructions = meter P, then output:NORMAL
     NORMAL hands the surviving packets to OVS's built-in L2 switching, so
     forwarding still works without touching Member 1's controller.

Side effects worth knowing (measured in the evaluation, not assumed):
  - Packets from P no longer reach Member 1's priority-1 rules or the
    table-miss rule, so a limited host causes no further Packet-Ins.
  - The switch counts a packet on the flow (and on the port) BEFORE the
    meter drops it, so Member 2's DataPlanePacketRate keeps showing the
    attack while it is being limited; mitigation does not hide the attack
    from the detector and cause a premature release.

All messages are only built and sent here; a Barrier after each batch lets
the app measure when the switch has actually applied them.
"""


def install_rate_limit(dp, port, rate_pps, burst, cookie, priority):
    ofp, parser = dp.ofproto, dp.ofproto_parser
    meter_id = port
    band = parser.OFPMeterBandDrop(rate=int(rate_pps), burst_size=int(burst))
    dp.send_msg(parser.OFPMeterMod(
        dp, command=ofp.OFPMC_ADD,
        flags=ofp.OFPMF_PKTPS | ofp.OFPMF_BURST | ofp.OFPMF_STATS,
        meter_id=meter_id, bands=[band]))
    inst = [parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER),
            parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                         [parser.OFPActionOutput(ofp.OFPP_NORMAL)])]
    dp.send_msg(parser.OFPFlowMod(
        dp, cookie=cookie, priority=priority, command=ofp.OFPFC_ADD,
        match=parser.OFPMatch(in_port=port), instructions=inst))
    return meter_id


def remove_all(dp, cookie):
    """Delete every flow carrying our cookie, then all meters.

    No other app in this controller uses meters, so OFPM_ALL is safe here;
    if that changes, delete our meter ids one by one instead.
    """
    ofp, parser = dp.ofproto, dp.ofproto_parser
    dp.send_msg(parser.OFPFlowMod(
        dp, cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF,
        table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
        out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))
    dp.send_msg(parser.OFPMeterMod(dp, command=ofp.OFPMC_DELETE,
                                   meter_id=ofp.OFPM_ALL))


def barrier(dp):
    """Send a Barrier; returns its xid so the reply can be matched."""
    req = dp.ofproto_parser.OFPBarrierRequest(dp)
    dp.send_msg(req)
    return req.xid


def request_port_stats(dp):
    ofp, parser = dp.ofproto, dp.ofproto_parser
    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))

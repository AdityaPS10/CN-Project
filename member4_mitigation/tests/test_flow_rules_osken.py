"""Builds and SERIALIZES our OpenFlow messages with os-ken (no switch needed).

Catches wrong field names/types before they reach OVS. Needs os-ken, so run
it with the controller's python:
    ~/ryu-venv/bin/python -m unittest member4_mitigation.tests.test_flow_rules_osken -v
Skipped automatically under a python without os-ken.
"""
import unittest

try:
    from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser
    HAVE_OSKEN = True
except ImportError:
    HAVE_OSKEN = False


class FakeDatapath:
    def __init__(self):
        self.id = 1
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
        self.sent = []
        self._xid = 0

    def send_msg(self, msg):
        if msg.xid is None:
            self._xid += 1
            msg.set_xid(self._xid)
        msg.serialize()                 # raises if any field is wrong
        self.sent.append(msg)


@unittest.skipUnless(HAVE_OSKEN, "os-ken not installed in this python")
class TestFlowRules(unittest.TestCase):
    def setUp(self):
        from member4_mitigation import flow_rules
        self.fr = flow_rules
        self.dp = FakeDatapath()

    def test_install_rate_limit(self):
        meter_id = self.fr.install_rate_limit(self.dp, 3, 10, 10, cookie=0x4D34, priority=100)
        self.assertEqual(meter_id, 3)
        meter, flow = self.dp.sent
        o = ofproto_v1_3
        self.assertEqual((meter.command, meter.meter_id), (o.OFPMC_ADD, 3))
        self.assertTrue(meter.flags & o.OFPMF_PKTPS)
        self.assertEqual((meter.bands[0].rate, meter.bands[0].burst_size), (10, 10))
        self.assertEqual((flow.cookie, flow.priority), (0x4D34, 100))
        self.assertEqual(flow.match["in_port"], 3)
        self.assertEqual(flow.instructions[0].meter_id, 3)
        self.assertEqual(flow.instructions[1].actions[0].port, o.OFPP_NORMAL)

    def test_remove_all_and_barrier(self):
        self.fr.remove_all(self.dp, 0x4D34)
        xid = self.fr.barrier(self.dp)
        flow_del, meter_del, bar = self.dp.sent
        o = ofproto_v1_3
        self.assertEqual((flow_del.command, flow_del.cookie, flow_del.cookie_mask),
                         (o.OFPFC_DELETE, 0x4D34, 0xFFFFFFFFFFFFFFFF))
        self.assertEqual((meter_del.command, meter_del.meter_id), (o.OFPMC_DELETE, o.OFPM_ALL))
        self.assertEqual(bar.xid, xid)

    def test_port_stats_request(self):
        self.fr.request_port_stats(self.dp)
        self.assertEqual(self.dp.sent[0].port_no, ofproto_v1_3.OFPP_ANY)


if __name__ == "__main__":
    unittest.main()

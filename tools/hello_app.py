"""Trivial os_ken app used only to sanity-check the custom launcher
(tools/osken_run.py) actually starts the controller and OpenFlow listener."""
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3


class HelloApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HelloApp, self).__init__(*args, **kwargs)
        self.logger.info("HelloApp loaded OK under os_ken AppManager.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Switch connected: dpid=%s", ev.msg.datapath_id)

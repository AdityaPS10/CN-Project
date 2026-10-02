#!/usr/bin/env python3
"""
Step 2 sanity-check topology: 1 OVS switch (OpenFlow 1.3) + 6 hosts,
pointed at our os-ken controller on 127.0.0.1:6653.

h1 is earmarked as the "server" (destination) for later steps.
h2-h6 are earmarked as traffic-source hosts.

Run (needs root, Mininet requires it):
    sudo python3 topo/basic_topo.py

This drops you into the Mininet CLI once the network is up. From there:
    mininet> pingall          # verify full connectivity through the controller
    mininet> h2 ping -c2 h1   # single flow check
    mininet> exit             # tear down cleanly

Requires the controller to already be running separately:
    source ~/ryu-venv/bin/activate
    python3 tools/osken_run.py controller/simple_switch_13.py
"""
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink


def build():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    c0 = net.addController('c0', controller=RemoteController,
                            ip='127.0.0.1', port=6653)

    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # h1 = server/victim. h2-h6 = traffic-source hosts for later steps.
    hosts = []
    for i in range(1, 7):
        h = net.addHost('h%d' % i, ip='10.0.0.%d/24' % i)
        hosts.append(h)
        net.addLink(h, s1)

    net.start()
    print("\n[basic_topo] Network is up. Hosts: %s (h1 = server)\n" %
          ", ".join(h.name for h in hosts))
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build()

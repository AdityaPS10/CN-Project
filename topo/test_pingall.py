#!/usr/bin/env python3
"""
Non-interactive Step 2 verification: builds the same topology as
basic_topo.py, runs pingall, prints flow tables, and tears down cleanly.
Requires the os-ken controller already running (tools/osken_run.py
controller/simple_switch_13.py) and root (run with sudo).
"""
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel
from mininet.link import TCLink
import subprocess
import sys


def build_and_test():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    hosts = []
    for i in range(1, 7):
        h = net.addHost('h%d' % i, ip='10.0.0.%d/24' % i)
        hosts.append(h)
        net.addLink(h, s1)

    net.start()
    print("\n=== Network started: s1 + %d hosts (h1=server) ===\n" % len(hosts))

    print("=== Checking OVS protocol version on s1 ===")
    out = subprocess.run(['sudo', '-n', 'ovs-vsctl', 'get', 'bridge', 's1', 'protocols'],
                          capture_output=True, text=True)
    print("s1 protocols:", out.stdout.strip(), out.stderr.strip())

    print("\n=== Running pingall ===")
    drop_pct = net.pingAll()
    print("\n=== pingall drop percentage: %.1f%% ===" % drop_pct)

    print("\n=== Flow table on s1 after pingall (should show learned MAC flows) ===")
    out = subprocess.run(['sudo', '-n', 'ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                          capture_output=True, text=True)
    print(out.stdout)
    if out.stderr:
        print("stderr:", out.stderr)

    net.stop()

    if drop_pct > 0:
        print("\nFAIL: packet loss detected (%.1f%% dropped)" % drop_pct)
        sys.exit(1)
    else:
        print("\nPASS: 0% dropped, full connectivity via controller confirmed")


if __name__ == '__main__':
    setLogLevel('info')
    build_and_test()

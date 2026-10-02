"""
Topology definition for use with `mn --custom topo/custom_topo.py --topo mytopo`.
1 switch + 6 hosts. h1 = server/victim, h2-h6 = traffic sources.
"""
from mininet.topo import Topo


class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        for i in range(1, 7):
            h = self.addHost('h%d' % i, ip='10.0.0.%d/24' % i)
            self.addLink(h, s1)


topos = {'mytopo': (lambda: MyTopo())}

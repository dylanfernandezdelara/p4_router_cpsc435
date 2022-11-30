from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')
        cpu1 = self.addHost('cpu1', ip='100.0.1.1')
        self.addLink(cpu1, switch, port2=1)

        for i in range(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

class TriTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Set up 3 routers
        s1 = self.addSwitch('s1')
        cpu1 = self.addHost('cpu1', ip='100.0.1.1')
        self.addLink(cpu1, s1, port2=1)

        s2 = self.addSwitch('s2')
        cpu2 = self.addHost('cpu2', ip='100.0.2.1')
        self.addLink(cpu2, s2, port2=1)

        s3 = self.addSwitch('s3')
        cpu3 = self.addHost('cpu3', ip='100.0.3.1')
        self.addLink(cpu3, s3, port2=1)

        self.addLink(s1, s2, port1=2, port2=2)
        self.addLink(s1, s3, port1=5, port2=5)
        self.addLink(s3, s2, port1=3, port2=3)

        h1 = self.addHost('h1', ip='100.0.1.10')
        self.addLink(h1, s1, port2=4)
        h2 = self.addHost('h2', ip='100.0.2.10')
        self.addLink(h2, s2, port2=4)
        h3 = self.addHost('h3', ip='100.0.3.10')
        self.addLink(h3, s3, port2=4)

class RingTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switches = []

        for i in range(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            switch = self.addSwitch('s%d' % i)
            self.addLink(host, switch, port2=1)
            switches.append(switch)

        # Port 2 connects to the next switch in the ring, and port 3 to the previous
        for i in range(n):
            self.addLink(switches[i], switches[(i+1)%n], port1=2, port2=3)
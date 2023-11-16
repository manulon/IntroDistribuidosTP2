from mininet.topo import Topo

class ParseError(Exception):
    pass

class Topologia(Topo):
    def __init__(self, switches=1):
        try:
            switches = int(switches)
        except ValueError:
            raise ParseError
            
        if switches < 1:
            raise ParseError

        print("Starting Topology of %s" % (switches))

        Topo.__init__(self)

        list_switches = []
        list_hosts = []

        print("Adding switch: s0")
        s0 = self.addSwitch('s0')
        list_switches.append(s0)

        last_switch = s0

        for i in range(1, switches):
            switch_name = 's%i' % (i)

            print("Adding switch: %s" % (switch_name))
            s = self.addSwitch(switch_name)
            list_switches.append(s)

            print("Adding links between: %s and %s" % (last_switch, s))
            self.addLink(last_switch, s)
            
            last_switch = s
        
        # hosts left
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')

        # hosts right
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')

        list_hosts.append(host1)
        list_hosts.append(host2)
        list_hosts.append(host3)
        list_hosts.append(host4)
        

        print("Adding links between: %s and %s" % (host1, s0))
        self.addLink(host1, s0)

        print("Adding links between: %s and %s" % (host2, s0))
        self.addLink(host2, s0)

        print("Adding links between: %s and %s" % (host3, last_switch))
        self.addLink(host3, last_switch)

        print("Adding links between: %s and %s" % (host4, last_switch))
        self.addLink(host4, last_switch)

        self._print_topology(list_hosts, list_switches)

    def _print_topology(self, hosts, switches):
        h00 = hosts[0]
        h01 = hosts[1]
        h10 = hosts[2]
        h11 = hosts[3]

        print('')
        print(h00 + "-----" + "\t" * (len(switches)) + "-----" + h10)
        print("\t" + "-----".join(switches))
        print(h01 + "-----" + "\t" * (len(switches)) + "-----" + h11)
        print('')


topos = {'topologiaCustom': (lambda x:  Topologia(x))}
   


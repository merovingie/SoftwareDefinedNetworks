from os import link
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI

# from time import clock, sleep
from threading import Timer


import sys
import subprocess
import ast 
import json

from collections import defaultdict

import time

def parse_link_config(file_name):
    link_config = {}
    print(f'Reading {file_name} for link data')
    file = open(file_name)
    link_json = json.load(file)
    for l in link_json:
        key = str(l["input_port"]) + str(l["output_port"])
        l['bw'] = l['bandwidth']
        l['delay'] = str(l['latency']) + str("ms")
        link_config[key] = l
    return link_config

host_link_config = dict(bw=100, delay="2ms")
link_config = parse_link_config('link_config.json')

def startIperfServers(net: Mininet):
    print('Starting iperf3 servers on all hosts')
    for h in net.hosts:
        h.cmd('iperf3 -s &')
    print('All hosts now running an iperf3 server')

def runTest(client: str, server: str, run_time: int, bw: int, net: Mininet, id):
    #print(f'Running iperf test between {client} and {server} for {run_time} seconds using {bw}Mb/s')
    c, s = net.get(client, server)
    destinationIp = s.IP()
    epoch_time = int(time.time())
    c.cmd(f'iperf3 -c {destinationIp} -t {run_time} -b {bw}M > {id}_{epoch_time}_result.txt &')
    #print(f'Test complete')
    return

def scheduleIperfTests(file_name: str, net: Mininet):
    file = open(file_name)
    test_json = json.load(file)

    for test in test_json:
        t = Timer(
                test['begin'],
                runTest,
                [
                    test['client'],
                    test['server'],
                    test['duration'],
                    test['bandwidth'],
                    net,
                    test['id'] or uuid.uuid4()
                ]
            )
        t.start()
    print('Finished scheduling all tests!')

class simplestTopo(Topo):
    # 'Simple loop topology'

    def __init__(self):
        # 'Create custom loop topo.'

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        ## Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')



        ## Add switches
        switch1 = self.addSwitch('s1')

        # Add Links

        # Adding links between switches and hosts
        self.addLink(switch1, host1, 1, 0, **link_config['10'])
        self.addLink(switch1, host2, 2, 0, **link_config['10'])


def simplestTest():
    topo = simplestTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    # net.start()
    CLI(net)
    net.stop()
class complexTopo(Topo):
    # 'Simple loop topology'

    def __init__(self):
        # 'Create custom loop topo.'

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        ## Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')


        ## Add switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')

        # Add Links
        self.addLink(switch1, switch2, 2, 1, **link_config['21'])
        self.addLink(switch2, switch3, 2, 1, **link_config['21'])
        self.addLink(switch1, switch4, 3, 2, **link_config['32'])
        self.addLink(switch3, switch5, 2, 3, **link_config['23'])
        self.addLink(switch4, switch5, 1, 2, **link_config['12'])
        self.addLink(switch4, switch2, 3, 3, **link_config['33'])

        # Adding links between switches and hosts
        self.addLink(switch1, host1, 1, 0, **link_config['10'])
        self.addLink(switch5, host2, 1, 0, **link_config['10'])
        self.addLink(switch5, host3, 4, 0, **link_config['10'])
        self.addLink(switch3, host4, 3, 0, **link_config['10'])


def complexTest():
    topo = complexTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    # net.start()
    CLI(net)
    net.stop()

class proactiveTopo(Topo):
    # 'Simple loop topology'

    def __init__(self):
        # 'Create custom loop topo.'

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        ## Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')


        ## Add switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')
        switch6 = self.addSwitch('s6')


        # Add Links
        self.addLink(switch1, switch2, 3, 1, **link_config['31'])
        self.addLink(switch2, switch4, 2, 3, **link_config['23'])
        self.addLink(switch1, switch3, 2, 1, **link_config['21'])
        self.addLink(switch3, switch4, 2, 2, **link_config['22'])
        self.addLink(switch1, switch5, 4, 1, **link_config['41'])
        self.addLink(switch5, switch4, 2, 4, **link_config['24'])
        self.addLink(switch1, switch6, 5, 1, **link_config['51'])
        self.addLink(switch6, switch4, 2, 5, **link_config['25'])

        # Adding links between switches and hosts
        self.addLink(switch1, host1, 1, 0, **link_config['10'])
        self.addLink(switch4, host2, 1, 0, **link_config['10'])

def proactiveTest():
    topo = proactiveTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=False)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    net.start()
    # net.staticArp()

    CLI(net)
    net.stop()

class widestTopo(Topo):
    # 'Simple loop topology'

    def __init__(self):
        # 'Create custom loop topo.'

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        ## Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')


        ## Add switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')


        # Add Links
        self.addLink(switch1, switch2, 3, 1, **link_config['31'])
        self.addLink(switch2, switch4, 2, 3, **link_config['23'])
        self.addLink(switch1, switch3, 2, 1, **link_config['21'])
        self.addLink(switch3, switch4, 2, 2, **link_config['22'])


        # Adding links between switches and hosts
        self.addLink(switch1, host1, 1, 0, **link_config['10'])
        self.addLink(switch4, host2, 1, 0, **link_config['10'])

def widestTest():
    topo = widestTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    # net.start()
    CLI(net)
    net.stop()

class shortestTopo(Topo):
    # 'Simple loop topology'

    def __init__(self):
        # 'Create custom loop topo.'

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        ## Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')


        ## Add switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')

        # Add Links
        self.addLink(switch1, switch2, 2, 1, **link_config['21'])
        self.addLink(switch2, switch3, 2, 1, **link_config['21'])
        self.addLink(switch1, switch4, 3, 2, **link_config['32'])
        self.addLink(switch3, switch5, 2, 3, **link_config['23'])
        self.addLink(switch4, switch5, 1, 2, **link_config['12'])

        # Adding links between switches and hosts
        self.addLink(switch1, host1, 1, 0, **link_config['10'])
        self.addLink(switch5, host2, 1, 0, **link_config['10'])

def shortestTest():
    topo = shortestTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    # net.start()
    CLI(net)
    net.stop()

class customTopo(Topo):
    """create topology with numCore core switches
    numEdge edge switches, hostsPerEdge, bw bandwidth, delay"""

    def build(self, numCores=3, numEdges=4, hostsPerEdge=2):
        # Write tree construction here
        # prepare arrays to carry objects created
        Core = []
        Edge = []
        Host = []
        # numCores = 3
        # numEdges = 4
        # hostsPerEdge = 2

        # create Core Switches
        for i in range(1, numCores + 1):
            # print('s' + str(i+numEdges))
            Core.append(self.addSwitch("C{}".format(i + numEdges), dpid=int2dpid(i + numEdges), protocols='OpenFlow13'))
        # Create Edge Switches
        for i in range(1, numEdges + 1):
            # print('s' + str(i))
            Edge.append(self.addSwitch("E{}".format(i + numEdges), dpid=int2dpid(i), protocols='OpenFlow13'))
        # Create Hosts
        for i in range(1, ((hostsPerEdge * numEdges) + 1)):
            Host.append(self.addHost("h{}".format(i)))

        # Create links per configuration between Core and Edge layers
        configuration = dict(bw=100, delay=0, max_queue_size=100, loss=0, use_htb=True)
        for i in range(0, len(Core)):
            for e in range(0, len(Edge)):
                self.addLink(Core[i], Edge[e], **configuration)

        # Create links per configuration between Edge and Hosts
        h = 0
        for i in range(0, len(Edge)):
            # print(i , h)
            self.addLink(Edge[i], Host[h], **configuration)
            self.addLink(Edge[i], Host[h + 1], **configuration)
            h += 2


def customTest():
    numEdges = 4
    hostsPerEdge = 2
    Hosts = []

    topo = customTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None, autoStaticArp=True)

    print("Start RYU controller and continue. (Press Enter)")
    input()

    net.addController('rmController', controller=RemoteController,
                      ip='127.0.0.1', port=6633)
    net.start()

    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    # print("Testing network connectivity")
    # net.pingAll()
    CLI(net)

    # dumpNodeConnections(net.hosts)
    # print("Collection Host array")
    # for i in range(1, (numEdges * hostsPerEdge) + 1):
    #     Hosts.append(net.get('h{}'.format(i)))
    #
    # # test Ipert between hosts
    # for i in range(len(Hosts) - 1):
    #     net.iperf((Hosts[i], Hosts[i + 1]))
    # # jump back to CLI
    # CLI(net)

    # Clean UP
    net.stop()


class SimpleTopo(Topo):
    # 'Simple loop topology'
 
    def __init__(self):
        # 'Create custom loop topo.'
 
        # Initialize topology
        Topo.__init__(self)
 
        # Add hosts and switches
        ## Add hosts        
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')

        ## Add switches
        switch1 = self.addSwitch('s1') 
        switch2 = self.addSwitch('s2')    
        switch3 = self.addSwitch('s3')  
        switch4 = self.addSwitch('s4')
        
        # Add Links
        self.addLink(switch1, switch2, 2, 3, **link_config['23'])
        self.addLink(switch2, switch4, 2, 1, **link_config['21'])
        self.addLink(switch4, switch3, 2, 2, **link_config['22'])
        self.addLink(switch3, switch1, 1, 3, **link_config['13'])  

        # Adding links between switches and hosts
        self.addLink(switch1, host1, 1, 0, **link_config['10'])
        self.addLink(switch4, host2, 3, 0, **link_config['30'])
        self.addLink(switch4, host3, 4, 0, **link_config['40'])

def simpleTest():
    topo = SimpleTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    startIperfServers(net)
    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)
    # net.start()
    CLI(net)
    net.stop()


#https://distrinet-emu.github.io/Mininet_compatibility.html function to calculate hex dpid that mininet would accept
def int2dpid(dpid):
      dpid = hex(dpid)[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid

 



def dump_flows(switch_str):
    return "-----------dump-flows " + switch_str + "\n" + subprocess.check_output(["ovs-ofctl","-O","OpenFlow13","dump-flows",switch_str])


def test_from_config(topo_name):
    # initialize topology
    if topo_name == 'SimpleTopo':
        topo = SimpleTopo()
    else:
        print('invalid topology name supplied')
        return

    net = Mininet(topo=topo,
                  host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.start()
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')

    tests = [simpleTest, customTest, shortestTest, widestTest, proactiveTest, complexTest, simplestTest]
    for i in range(len(tests)):
        print("%d: %s" % (i, str(tests[i])))
    try:
        test_ind = int(sys.argv[1])
        print("test_ind: ", test_ind)
    except:
        pass
    else:
        tests[test_ind]()
        exit()


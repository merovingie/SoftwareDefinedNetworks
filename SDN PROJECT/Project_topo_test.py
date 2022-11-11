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
import uuid

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


class SimpleTopo(Topo):
    'Simple loop topology'
 
    def __init__(self):
        'Create custom loop topo.'
 
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


#https://distrinet-emu.github.io/Mininet_compatibility.html function to calculate hex dpid that mininet would accept
def int2dpid(dpid):
      dpid = hex(dpid)[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid

 
# topos = {'topology': (lambda: SimpleTopo())}

def simpleTest():
    topo = SimpleTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    net.start()
    startIperfServers(net)

    print("Start RYU controller and continue. (Press Enter)")
    input()

    scheduleIperfTests('test_plan.json', net)

    CLI(net)
    net.stop()

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
                  host=CPULimitedHost, link=TCLink, controller=RemoteController, autoSetMacs=True)
    net.start()
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')

    tests = [simpleTest]
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


#!/usr/bin/python

#Copyright (c) 2016 Enrique Saurez

#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from ssl import ALERT_DESCRIPTION_RECORD_OVERFLOW
from turtle import addshape
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info, warn
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
import icecream as ic

class customTopo(Topo):
    """create topology with numCore core switches
    numEdge edge switches, hostsPerEdge, bw bandwidth, delay"""

    def build(self, numCores = 3, numEdges=4, hostsPerEdge=2, bw = 5, delay = None):

        #Write tree construction here
	#prepare arrays to carry objects created
        Core = []
        Edge = []
        Host = []
        
        #create Core Switches
        for i in range(1, numCores+1):
            #print('s' + str(i+numEdges))
            Core.append(self.addSwitch("C{}".format(i+numEdges), dpid=int2dpid(i+numEdges), protocols='OpenFlow13'))
        #Create Edge Switches
        for i in range(1, numEdges+1):
            #print('s' + str(i))
            Edge.append(self.addSwitch("E{}".format(i+numEdges), dpid=int2dpid(i), protocols='OpenFlow13'))
        #Create Hosts
        for i in range(1, ((hostsPerEdge*numEdges)+1)):
            Host.append(self.addHost("h{}".format(i)))

        #Create links per configuration between Core and Edge layers
        configuration = dict(bw=bw, delay=delay, max_queue_size=100, loss=0, use_htb=True)
        for i in range(0, len(Core)):
            for e in range(0, len(Edge)):
                self.addLink(Core[i], Edge[e], **configuration)
        
        #Create links per configuration between Edge and Hosts
        h = 0
        for i in range(0, len(Edge)):
            #print(i , h)
            self.addLink(Edge[i], Host[h], **configuration)
            self.addLink(Edge[i], Host[h+1], **configuration)
            h += 2
        
            
        


def test():
    topo = customTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)


    print("Start RYU controller and continue. (Press Enter)")
    input()

    net.addController('rmController', controller=RemoteController,
            ip='127.0.0.1', port=6633)
    net.start()

    print("Testing network connectivity")
    net.pingAll()
    CLI(net)
    #dumpNodeConnections(net.hosts)
    print("Testing bandwidth between h1 and h4")
    h1, h4 = net.get('h1', 'h4')
    net.iperf((h1, h4))
    #CLI(net)
    net.stop()
    
#https://distrinet-emu.github.io/Mininet_compatibility.html function to calculate hex dpid that mininet would accept
def int2dpid(dpid):
      dpid = hex(dpid)[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid


if __name__ == '__main__':
    setLogLevel('info')
    test()

from mininet.topo import Topo
 
 
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
        # Add links (Use the switches in then node1 space)
        # Link function prototye:
        ## mininet.net.Mininet.addLink( self, node1, node2, port1 = None, port2 = None, cls = None, params ) 
        #switches to switches
        # configuration = dict(bw=10, delay=0, max_queue_size=100, loss=0, use_htb=True)     
        # self.addLink(switch1, switch2, port1 =2, port2=1,**configuration)
        self.addLink(switch1, switch2, 2, 1)
        # self.addLink(switch2, switch4, port1 =2, port2=1,**configuration)
        self.addLink(switch2, switch4, 2, 1)
        # self.addLink(switch4, switch3, port1 =2, port2=2,**configuration)
        self.addLink(switch4, switch3, 2, 2)
        # self.addLink(switch3, switch1, port1 =1, port2=3,**configuration)
        self.addLink(switch3, switch1, 1, 3)  

        # Adding links between switches and hosts
        # self.addLink(switch1, host1, port1 =1, port2=0,**configuration)
        self.addLink(switch1, host1, 1, 0)
        # self.addLink(switch4, host2, port1 =3, port2=0,**configuration)
        self.addLink(switch4, host2, 3, 0) 
        # self.addLink(switch4, host3, port1 =4, port2=0,**configuration)
        self.addLink(switch4, host3, 4, 0)


#https://distrinet-emu.github.io/Mininet_compatibility.html function to calculate hex dpid that mininet would accept
def int2dpid(dpid):
      dpid = hex(dpid)[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid

 
topos = {'topology': (lambda: SimpleTopo())}


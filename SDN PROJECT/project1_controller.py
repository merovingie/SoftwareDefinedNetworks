# Copyright (C) 2016 Enrique Saurez Georgia Institute of Technology
# Copyright (C) 2016 Li Cheng BUPT www.muzixing.com.
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Contributors
#    Li Cheng, (http://www.muzixing.com)
#    Enrique Saurez (esaurez@gatech.edu)
import json

from asyncio import DatagramProtocol

from ryu.lib import stplib
from ryu.lib import dpid as dpid_lib

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, ipv4, ipv6
from ryu.lib import mac
 
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
# import networkx as nx

import igraph as ig
from collections import defaultdict
from operator import attrgetter

from ryu.lib import hub
from ryu import cfg
import functools
import ast
# import matplotlib.pyplot as plt
# import copy
from collections import deque

from threading import Thread
from time import sleep


# Events for topology Mapping:
# EventOFPPortStateChange
# EventOFPPortStatus
#

# rules with the highest priority is applied first
# packetOUT is for PACKET_INT becasue sendint he all the max buffer tot he controller
adjacency=defaultdict(lambda:defaultdict(lambda:None))

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'stplib': stplib.Stp}
 
    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('T1', default=10),
            cfg.IntOpt('T2', default=30),
            cfg.IntOpt('S1', default=5),
            cfg.StrOpt('strategy', default='shortest_path')
        ])
        print(f'T1 = {CONF.T1}')
        print(f'T2 = {CONF.T2}')
        print(f'S1 = {CONF.S1}')
        print(f'Strategy = {CONF.strategy}')
        self.T1: int = CONF.T1
        self.T2: int = CONF.T2
        self.S1: int = CONF.S1
        self.strategy: str = CONF.strategy
        self.samples = []
        self.average_bps_links = {}
        self.mac_to_port = {} #start mac table
        self.datapaths = {}
        self.FLAGS = True
        self.topology_api_app = self
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.topo_raw_hosts = []
        self.link_stats = {}
        self.graph = ig.Graph(directed=True)
        self.hosts_to_switch = {}
        self.rebalancing = False

        self.BYTES_PER_MEGABIT = 125000

        self.graph = ig.Graph(directed=True)

        self.stp = kwargs['stplib']
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                      {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                      {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                      {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)
        
        # if self.strategy != 'proactive':
        #     self.redistribute_on = False
        # else:
        #     self.monitoring_on = True

        print('monitoring every', self.T1, 'seconds')
        print('rebalancing every', self.T2, 'seconds')
        print(f'keeping {self.S1} bw samples per link')


        # configure link parameters
        self.link_config = {}
        self.parse_link_config('link_config.json', self.link_config)
        #print(f'parsed link_config:\r\n{self.link_config}')

        # spawn monitor and rebalance threads
        self.monitor_thread = hub.spawn(self._monitor)
        if self.strategy == 'proactive':
            self.rebalance_thread = hub.spawn(self._rebalance)

    def parse_link_config(self, file_name, link_config):
        print(f'Reading {file_name} for link data')
        file = open(file_name)
        link_json = json.load(file)
        for l in link_json:
            key = str(l["input_port"]) + str(l["output_port"])
            l['bw'] = l['bandwidth']
            l['lat'] = l['latency']
            link_config[key] = l

    # Ports Discovery
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
            print("port added ", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
            print("port deleted ", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
            print("port modified ", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
            print("Illeagal port state %s %s", port_no, reason)

    #topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def _handler_switch_enter(self, ev):
        self.topo_raw_switches = get_switch(self, None)
        # switches_conf = json.dumps([switch.to_dict() for switch in self.topo_raw_switches])
        # print("Switches Json")
        # print(switches_conf)
        # print(" \t" + "Current Switches:")
        # for s in self.topo_raw_switches:
        #     print (" \t\t" + str(s))
        self.graph.add_vertex(str(ev.switch.dp.id))
        print("Switch %d entered" % ev.switch.dp.id)
        pass

    # This event is fired when a switch leaves the topo. i.e. fails.
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def _handler_switch_leave(self, ev):
        # self.logger.info("Not tracking Switches, switch leaved.")
        print("Not tracking Switch, switch left.", ev.switch.dp.id)
        self.graph.delete_vertices(str(ev.switch.dp.id))
        pass

    @set_ev_cls([event.EventLinkAdd, event.EventLinkDelete])
    def _event_link_handler(self, ev):
        print("Link Added:", ev.link.src.dpid, ev.link.src.port_no, ev.link.dst.dpid, ev.link.dst.port_no)
        self.topo_raw_links = get_link(self.topology_api_app, None)
        try:
            bw = self.link_config[str(ev.link.src.port_no) + str(ev.link.dst.port_no)]["bw"]
            lat = self.link_config[str(ev.link.src.port_no) + str(ev.link.dst.port_no)]["lat"]
        except KeyError as e:
            bw = 100
            lat = 2

        bw *= self.BYTES_PER_MEGABIT * self.T1

        # links_conf = json.dumps([link.to_dict() for link in self.topo_raw_links])
        # print("Links Json")
        # print(links_conf)
        # print(" \t" + "Current Links:")
        # for l in self.topo_raw_links:Link added
        #     print(" \t\t" + str(l))
        try:
            self.graph.es.find(src_dpid=ev.link.src.dpid, dst_dpid=ev.link.dst.dpid)
            print("Duplicated link_add event tried to add to graph")
            return
        except:
            pass

        self.graph.add_edge(str(ev.link.src.dpid), str(ev.link.dst.dpid),
            src_dpid=ev.link.src.dpid,
            dst_dpid=ev.link.dst.dpid,
            src_port=ev.link.src.port_no,
            dst_port=ev.link.dst.port_no,
            bw=bw,
            lat=lat,
            estimated_bw=bw,
            last_bws=deque(maxlen=self.S1),
            last_num_bytes=0)
        
        print("Link added", ev.link)
        print(self.graph)
        # ig.plot(self.graph)
        

    # Host detection ...
    @set_ev_cls([event.EventHostAdd, event.EventHostDelete])
    def _event_host_handler(self, ev):
        # datapath = ev.msg.datapath
        # dpid = datapath.id
        # print("this is host handler DPID",dpid)
        self.topo_raw_hosts = get_host(self.topology_api_app, None)
        # hosts_conf = json.dumps([host.to_dict() for host in self.topo_raw_hosts])
        # print("Host Json")
        # print(hosts_conf)
        print(" \t" + "Current Hosts:")
        for h in self.topo_raw_hosts:
            print("\t\t" + str(h))
            print("this is h.mac", h.mac)
            self.hosts_to_switch[h.mac] = h.port.dpid

    # DEAD_DISPATCHER is disconnection of a connection event
    # MAIN_DISPATCHER normal status
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


  
    # def add_flow(self, datapath, match, actions):
    #     """
    #     Pushes a new flow to the datapath (=switch)
    #     :type datapath: ryu.controller.controller.Datapath
    #     :type in_port: int - input port
    #     :type dst: string  - destination information
    #     :type actions: list
    #     :return: None
    #     :rtype: None
    #     """
    #     ofproto = datapath.ofproto
    #
    #     parser = datapath.ofproto_parser
    #
    #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    #
    #     mod = parser.OFPFlowMod(datapath=datapath, priority=1, cookie=0, command=ofproto.OFPFC_ADD, idle_timeout =0, hard_timeout=0, match=match, instructions=inst)
    def add_flow(self, datapath, match, actions, priority=1, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        '''
        # might fix the bug
        if buffer_id: # just in case the switch couldnt forward the packet it gets stored to buffer_id
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=1, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        '''
 
    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.hosts_to_switch:
            print('deleting flows for dst:', dst, ' on datapath:', datapath.id)
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    def switch_features_handler(self , ev):
        """
        Called during handshake, defines rule to send all unknown packets to controller
        :type ev: ryu.controller.ofp_event.EventOFPSwitchFeatures
        :return: None
        :rtype: None
        """
        
        datapath = ev.msg.datapath
        dpid = datapath.id

        print("switch_features_handler is called: ", dpid)

     
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        #this is the message out packet_out and OFPActionOut to specify a switfch port
        #OFPP_CONTROLLER & OFPCML_NO_BUFFER no buffer should be applied and the whole message should be sent to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        # OFPIT_APPLY_ACTIONS apply actions immedialty
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        priority=0, instructions=inst)

        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
        This function creates the packet that is going to be sent to the switch
        :type datapath: ryu.controller.controller.Datapath
        :type buffer_id: integer - ID assigned by datapath
        :type src_port: integer - source port
        :type dst_port: integer- output port
        :type data: Packet data of a binary type value or an instances of packet.Packet.
        :return: packet to be sent 
        :rtype: OFPPacketOut
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data
        # used to build the packet_out
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
        This function sents the packet to the corresponding switch 
        :type datapath: ryu.controller.controller.Datapath
        :type buffer_id: integer - ID assigned by datapath
        :type src_port: integer - source port
        :type dst_port: integer- output port
        :type data: Packet data of a binary type value or an instances of packet.Packet.
        :return: packet to be sent 
        :rtype: OFPPacketOut
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            #that's sending the outmessage from open flow class
            datapath.send_msg(out)

    def flood(self, msg):
        """
        This function sents a message to flood the network to obtain ------------. What are we obtaining here? 
        :type msg: ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn - An object which describes the corresponding OpenFlow message. 
        :return: None 
        :rtype: None
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        """
        This forwards the ARP message, to obtain the MAC address, depending if it is now different actions are taken.
        :type msg: ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn - An object which describes the corresponding OpenFlow message. 
        :type src_ip: string 
        :type dst_ip: string
        :type eth_pkt: ryu.lib.packet.ethernet
        :return: None 
        :rtype: None
        """

        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)

        #What is the difference if we know the mac address and if we don't
        #if we know the mac address that means we know which port and what ip associated with it..if we dont that's considered a miss
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to known host")
            print("Reply ARP to known host")
        else:
            print("Flooding for ARP")
            self.flood(msg)

    def mac_learning(self, dpid, src_mac, in_port):
        """
        If an unknown mac address is found, learn that for future packages
        :type dpip: string - name for the switch (datapath) 
        :type src_mac: string
        :type in_port: int 
        :return: if it was correctly learned 
        :rtype: Bool
        """
        # Initialize value on the dictionary
        self.mac_to_port.setdefault(dpid, {})
        #If the mac is already known
        if src_mac in self.mac_to_port[dpid]:
            #If the mac is comming from a different port that it was initiallly known
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            # Store port used for the given MAC address.
            self.mac_to_port[dpid][src_mac] = in_port
            if src_mac not in self.hosts_to_switch:
                self.hosts_to_switch[src_mac] = dpid
                self.link_stats.setdefault(src_mac, {})
            return True
        
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Called every time, when the controller receives a PACKET_IN message
        :type ev: ryu.controller.ofp_event.EventOFPPacketIn
        :return: None
        :rtype: None
        """
        if self.rebalancing:
            # drop all packets while rebalancing is in progress
            return

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.info("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        #packet_in
        msg = ev.msg
        #switch
        datapath = msg.datapath
        #protocol
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #switch xID
        dpid = datapath.id
        #which PORT
        in_port = msg.match['in_port']
        # print("packet handler in_port: ", in_port)
        # print("Packet coming on switch: ", dpid)
        
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)

        #arp.arp_ID
        arp_pkt = pkt.get_protocol(arp.arp)
        dst = eth.dst
        src = eth.src
        # print("packet coming src and dst ethernet:", src, dst)
        # Don't do anything with IPV6 packets.
        # parser for the decoding the packet.. serialize() is to encode
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []  #action empty drop packet ipv6
            # drop ipv6
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
            self.add_flow(datapath, match, actions)
            return 

        # ARP Protcol
        # if isinstance(arp_pkt, arp.arp):
        #     if self.mac_learning(dpid, eth.src, in_port) is False:
        #         self.logger.debug("ARP packet enter in different ports")
        #         print("ARP packet enter in different ports")
        #         return
	    # # Complete ARP protocol
        #     self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(arp_pkt, arp.arp):
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:

                # check IP Protocol and create a match for IP
                if eth.ethertype == ether_types.ETH_TYPE_IP:
                    ip = pkt.get_protocol(ipv4.ipv4)
                    srcip = ip.src
                    dstip = ip.dst
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,
                                            ipv4_dst=dstip
                                            )
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, match, actions, 1, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, match, actions, 1)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        # This is the focus of this workshop -> Process the IPv4 message
        if isinstance(ip_pkt, ipv4.ipv4):
            # # find the switch in the mac_to_port table
            mac_to_port_table = self.mac_to_port.get(dpid)
            # if mac_to_port_table is None:
            #     self.logger.info("Dpid is not in mac_to_port")
            #     return
            # #ethernet multi cast -->
            # pi = not (str(eth.dst) == '01:80:c2:00:00:0e')
            # packet_in_rcvd = ("\t\tpacket in s%s %s %s %s" % (dpid, eth.src, eth.dst, in_port))
            # if pi: print(packet_in_rcvd)
            #
            # # source and destination mac address of the ethernet packet
            # dst = eth.dst
            # src = eth.src
            #
            out_port = None
            # # "Known destination MAC address" -> We have seen this before
            # # print(mac_to_port_table)
            # # print(dst)
            # # print(self.hosts_to_switch)
            # # print(mac_to_port_table[dst])
            if dst in self.hosts_to_switch:
                dst_switch_dpid = self.hosts_to_switch[dst]
                dst_switch_vid = self.graph.vs.find(name=str(dst_switch_dpid)).index
                start_switch_vid = self.graph.vs.find(name=str(dpid)).index

                print('finding path from', dpid, 'to', dst_switch_dpid)

                if self.strategy == "shortest_path":
                    print('finding shortest_path')
                    path = self.graph.get_shortest_paths(str(dpid), str(dst_switch_dpid), output='epath')[0]
                elif self.strategy == "widest_path":
                    path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='bw')
                elif self.strategy == "proactive":
                    path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='estimated_bw')
                    print('using proactive rules. found path of bw: ', path_bw)
                    if path_bw <= 0:
                        print('effective bandwidth zero, reverting to original rules')
                        path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='bw')
                else:
                    print('invalid strategy parameters')
                    exit()

                if len(path) != 0:
                    print('found path:',)
                    for p in path:
                        print(self.graph.es[p]['src_dpid'])
                    out_port = self.graph.es[path[0]]['src_port']
                else:
                    print('same switch')
                    out_port = mac_to_port_table[eth.dst]

                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_src=eth.src, eth_dst=eth.dst, in_port=in_port,
                                        eth_type=eth.ethertype)
                print('\t\t\tadding flow on s', dpid, 'in:', in_port, 'out:', out_port, 'dst:', eth.dst)
                self.add_flow(datapath, match, actions)
                self.send_packet_out(datapath, msg.buffer_id, in_port,
                                     out_port, msg.data)

            else:
                out_port = ofproto.OFPP_FLOOD

                actions = [parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:

                    # check IP Protocol and create a match for IP
                    if eth.ethertype == ether_types.ETH_TYPE_IP:
                        ip = pkt.get_protocol(ipv4.ipv4)
                        srcip = ip.src
                        dstip = ip.dst
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_src=srcip,
                                                ipv4_dst=dstip
                                                )
                        # verify if we have a valid buffer_id, if yes avoid to send both
                        # flow_mod & packet_out
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, match, actions, 1, msg.buffer_id)
                            return
                        else:
                            self.add_flow(datapath, match, actions, 1)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)


                # if dpid == 1 and in_port == 1:
                #     # This is the special case for host 1 only do create create the group the first time
                #     if self.FLAGS is True:
                #         self.send_group_mod(datapath)
                #         self.FLAGS = False
                #     actions = [parser.OFPActionGroup(group_id=7)]
                #     match = parser.OFPMatch(in_port=in_port,
                #                             eth_type=eth.ethertype,
                #                             ipv4_src=ip_pkt.src)
                #     self.add_flow(datapath, match, actions)
                #     # asign output at 2
                #     self.send_packet_out(datapath, msg.buffer_id,
                #                          in_port, 2, msg.data)
                # else:
                #     #Normal flows
                #     # "Install a flow to avoid packet_in next time">
                #     out_port = mac_to_port_table[eth.dst]
                #     actions = [parser.OFPActionOutput(out_port)]
                #     match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                #                             eth_type=eth.ethertype)
                #    #Add the flow to the switch
                #     self.add_flow(datapath, match, actions)
                #     #Send packet to its destination
                #     self.send_packet_out(datapath, msg.buffer_id, in_port,
                #                          out_port, msg.data)
            # "Unknown destination MAC address"
            # else:
            #     # MAC is not Known
            #     if self.mac_learning(dpid, eth.src, in_port) is False:
            #         self.logger.debug("IPV4 packet enter in different ports")
            #         return
            #     else:
            #         # we don't know anything, so flood the network 
            #         self.flood(msg)

    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

    def widest_dijkstra(self, g, s, bw='bw'):
        previous = {}  # previous hops
        cap = {}  # capacities between nodes
        T = set()
        V = set(range(g.vcount()))  # Initially set of all nodes
        T.add(s)
        V.remove(s)
        cap[s] = float(100 * self.BYTES_PER_MEGABIT * self.T1) # links from host to switch are always bw 100 but not included in our graph
        # Initialize capacities
        for v in V:
            es_sv = g.es.select(_source=s, _target=v)
            if es_sv.count_multiple() == [1]:
                cap[v] = es_sv[bw][0]
                previous[v] = s
            else:
                cap[v] = 0.0
        while len(V) > 0:
            u = max(V, key=lambda x: cap[x])
            T.add(u)
            V.remove(u)
            # update capacities
            for v in V:
                es_uv = g.es.select(_source=u, _target=v)
                if es_uv.count_multiple() == [1]:
                    bw_uv = es_uv[bw][0]
                    if cap[v] < min(cap[u], bw_uv):
                        cap[v] =  min(cap[u], bw_uv)
                        previous[v] = u
        return cap, previous

    def get_edges_from_prev(self, g, s, d, prev):
        edges = []
        curr = d
        while curr != s:
            # print curr, g.vs[curr]['name']
            try:
                eid = g.es.find(_source=prev[curr], _target=curr).index
            except:
                return []
            edges.append(eid)
            curr = prev[curr]

        return edges[::-1]

    def widest_path(self, s, d, bw='bw'):
        cap, prev = self.widest_dijkstra(self.graph, s, bw)
        return self.get_edges_from_prev(self.graph, s, d, prev), cap[d]


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        print(f'starting monitor thread')
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.T1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  '
                         'out-port bytes    duration   hard_timeout  idle_timeout')
        self.logger.info('---------------- '
                         '-------- '
                         '-------- -------- --------   -----------   -----------')
        for stat in sorted([flow for flow in body if flow.priority == 1 and 'in_port' in flow.match and 'eth_dst' in flow.match and 'eth_src' in flow.match and 'eth_type' in flow.match],
                            key=lambda flow: (flow.match['in_port'])):
            self.logger.info('%016x %8x %8x %8d %8d %8d %8d',
                            ev.msg.datapath.id,
                            stat.match['in_port'],
                            stat.instructions[0].actions[0].port,
                            stat.byte_count, stat.duration_sec, stat.hard_timeout, stat.idle_timeout)
 
            dst = stat.match['eth_dst']
            src = stat.match['eth_src']

            if self.link_stats.get(src) is None:
                self.link_stats[src] = {}

            if self.link_stats[src].get(dst) is None:
                self.link_stats[src][dst] = dict(src=src, dst=dst,
                                            packets=0, last_byte_count=0,
                                            prev_counts=deque(maxlen=self.S1),
                                            avg_bytes=0)

            stats = self.link_stats[src][dst]
            stats['packets'] = stat.packet_count
            curr_bytes = stat.byte_count - stats['last_byte_count']
            stats['last_byte_count'] = curr_bytes
            stats['prev_counts'].append(curr_bytes)
            stats['avg_bytes'] = sum(stats['prev_counts'])/self.S1
        


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        port_byte_counts = defaultdict(int)

        self.logger.info('datapath         port     '
                         'rx-dropped  rx-bytes rx-error '
                         'tx-dropped  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            port_byte_counts[stat.port_no] += stat.tx_bytes
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_dropped, stat.rx_bytes, stat.rx_errors,
                            stat.tx_dropped, stat.tx_bytes, stat.tx_errors)
        
        for port in port_byte_counts:
            byte_count = port_byte_counts[port]
            src_vid = self.graph.vs["name"].index((str(ev.msg.datapath.id)))
            try:
                edge = self.graph.es.find(_source=src_vid, src_port=port)
            except ValueError as e:
                pass
            else:
                last_bw_used = (byte_count - edge['last_num_bytes'])
                edge['last_bws'].append(max(edge['bw'] - last_bw_used, 0))
                edge['estimated_bw'] = sum(edge['last_bws'])/self.S1
                edge['last_num_bytes'] = byte_count
    
    # get all flows for distribution
    def get_flows(self, epath, src, dst, info):
        flows = []

        # append flow for src
        dpid = self.hosts_to_switch[src]
        in_port = self.mac_to_port[dpid][src]

        if len(epath) == 0:
            if self.hosts_to_switch[dst] != dpid:
                return None

            out_port = self.mac_to_port[dpid][dst]
            flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

            return flows

        out_port = self.graph.es[epath[0]]['src_port']
        flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

        for i in range(len(epath)-1):
            es = self.graph.es[epath[i]]
            next_es = self.graph.es[epath[i+1]]

            # flow parameters
            dpid = es['dst_dpid']
            in_port = es['dst_port']
            out_port = next_es['src_port']

            # append the flow to be added later
            flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

            # updated the estimated_bw
            self.bw_print(epath[i])
            updated_bw = es['estimated_bw'] - info['avg_bytes']
            es['estimated_bw'] = max(0, updated_bw)
            self.bw_print(epath[i])

        # append flow for dst
        last_es = self.graph.es[epath[-1]]
        dpid = last_es['dst_dpid']
        in_port = last_es['dst_port']
        out_port = self.mac_to_port[dpid][dst]
        flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

        self.bw_print(epath[-1])
        updated_bw = last_es['estimated_bw'] - info['avg_bytes']
        last_es['estimated_bw'] = max(0, updated_bw)
        self.bw_print(epath[-1])

        return flows
    
    def _rebalance(self):
        print('starting rebalance thread')
        while True:
            hub.sleep(self.T2)
            print('Beginning rebalance')
            self.rebalancing = True
            self.rebalance_helper()
            self.rebalancing = False
            print('Rebalance complete')

    def rebalance_helper(self):
        # sort infos
        info_list = []
        for src in self.link_stats:
            for dst in self.link_stats[src]:
                info_list.append(self.link_stats[src][dst])

        info_list = sorted(info_list, key=lambda info:info['packets'], reverse=True)

        for info in info_list:
            print(info)

        # restore estimates to initial capacity
        estimates = self.graph.es['estimated_bw']
        self.graph.es['estimated_bw'] = list(self.graph.es['bw'])

        flows = []
        for info in info_list:
            src = info['src']
            dst = info['dst']
            print('-----------------------INFO\n\t', info)
            dst_switch_dpid = self.hosts_to_switch[dst]
            src_switch_dpid = self.hosts_to_switch[src]

            dst_vid = self.graph.vs.find(name=str(dst_switch_dpid)).index
            src_vid = self.graph.vs.find(name=str(src_switch_dpid)).index

            cap, prev = self.widest_dijkstra(self.graph, src_vid, bw='estimated_bw')
            if cap[dst_vid] > 0:
                src_port = self.mac_to_port[src_switch_dpid][src]
                dst_port = self.mac_to_port[dst_switch_dpid][dst]
                # print 'finding edges from vid', src_vid, 'to vid', dst_vid
                print('finding edges from switch_dpid', src_switch_dpid, 'to switch_dpid', dst_switch_dpid)
                epath = self.get_edges_from_prev(self.graph, src_vid, dst_vid, prev)
                print('\tpath(%d):' % (len(epath)))
                if len(epath) != 0:
                    for eid in epath:
                        print(self.graph.es[eid]['src_dpid'],)
                    print(self.graph.es[epath[-1]]['dst_dpid'])
                else:
                    print(self.hosts_to_switch[src])

                new_flows = self.get_flows(epath, src, dst, info)
                
                if new_flows is None:
                    print('some hosts appeared to be unreachable, not rebalancingrebalancing')
                    # restore old estimates
                    self.graph.es['estimated_bw'] = estimates
                    return
                flows += new_flows
                # print '\t----------------FLOWS:', len(flows)
                # print '\t------------NEW_FLOWS:', len(new_flows)
                print('\t\t', new_flows)
            else:
                print('some hosts appeared to be unreachable, not rebalancing')
                # restore old estimates
                self.graph.es['estimated_bw'] = estimates
                return

        # delete all flows
        for dpid in self.datapaths:
            print("trying to delete flows")
            print(dpid)
            self.delete_flow(self.datapaths[dpid])

        # install all the new flows
        for flow in flows:
            print('trying to install new flow on datapath', flow['dpid'])
            print('\tin_port', flow['in_port'], 'eth_src', flow['eth_src'], 'eth_dst', flow['eth_dst'], 'out_port', flow['out_port'])
            datapath = self.datapaths[flow['dpid']]
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(flow['out_port'])]
            match = parser.OFPMatch(in_port=flow['in_port'],
                                    eth_dst=flow['eth_dst'],
                                    eth_src=flow['eth_src'])
            self.add_flow(datapath, match, actions)


    def bw_print(self, eid, bw_key='estimated_bw'):
        bw = self.graph.es[eid][bw_key]
        bw = bw / self.BYTES_PER_MEGABIT / self.T1
        print(self.graph.es[eid]['src_dpid'], '->', self.graph.es[eid]['dst_dpid'], bw)
    
    def get_edges_from_prev(self, g, s, d, prev):
        edges = []
        curr = d
        while curr != s:
            try:
                eid = g.es.find(_source=prev[curr], _target=curr).index
            except:
                return []
            edges.append(eid)
            curr = prev[curr]

        return edges[::-1]

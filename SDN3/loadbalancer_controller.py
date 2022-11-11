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
 
from asyncio import DatagramProtocol
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, ipv4, ipv6
from ryu.lib import mac
 
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
 
# rules with the highest priority is applied first
# packetOUT is for PACKET_INT becasue sendint he all the max buffer tot he controller
class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {} #start mac table
        self.datapaths = {}
        self.FLAGS = True

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


  
    def add_flow(self, datapath, match, actions):
        """
        Pushes a new flow to the datapath (=switch)
        :type datapath: ryu.controller.controller.Datapath
        :type in_port: int - input port
        :type dst: string  - destination information 
        :type actions: list
        :return: None
        :rtype: None
        """
        #TODO: 1) Get the OpenFlow protocol from the datapath +
        #ofProto and the data parser are the neogiation of the openFlow 1.3 .. dp.ofproto
        ofproto = datapath.ofproto

        #TODO: 1) Get the Parser for the protocol from the datapath +
        parser =   datapath.ofproto_parser    

        #TODO: 1) Create the required instruction that indicates the operation +
        inst =  [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        #TODO: 1) Create the modify flow message with fields: datapath, match, cookie=0, command, idle_timeout =0, hard_timeout=0, priority=1 and instructions
        # Why do you think priority is one? + flow has to be higher priority ..why!!??
        # because the the rule is new installed and it needs to run first before any other rule like miss rule 

        mod = parser.OFPFlowMod(datapath=datapath, priority=1, cookie=0, command=ofproto.OFPFC_ADD, idle_timeout =0, hard_timeout=0, match=match, instructions=inst)

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

        datapath.send_msg(mod)
 
    #TODO: Final Questions - Do you know what is a decorator? What is it use in a Ryu Controller?
    #decorators are to add functionality to an orginal object method or class.. the use is add openflow layer functionality to the api.. in general speak.. research specifics
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    def switch_features_handler(self , ev):
        """
        Called during handshake, defines rule to send all unknown packets to controller
        :type ev: ryu.controller.ofp_event.EventOFPSwitchFeatures
        :return: None
        :rtype: None
        """
        print("switch_features_handler is called")
        #TODO: 1) Get the datapath (switch) from the ev object
        #switch object.. ev.msg is the packet_in
        datapath = ev.msg.datapath
        dpid = datapath.id

     
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        
        
        #TODO: Final Questions - Why do you think we need the empty Match?
        #install table miss flow entry
        #TODO: Final Questions - Why is it call "table-miss flow entry"?
        #should be the entry to process packetIN for the controller because where dont have a rule to match on the switch
        match = parser.OFPMatch()
        #this is the message out packet_out and OFPActionOut to specify a switfch port
        #OFPP_CONTROLLER & OFPCML_NO_BUFFER no buffer should be applied and the whole message should be sent to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        # OFPIT_APPLY_ACTIONS apply actions immedialty
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

        #TODO: Final Questions - Why is the priority zero here?
        #miss entry should be the least priority to execute after all other rules are exhausted with higher priority
        #command (ofproto_v1_3.OFPFC_ADD)
        # Specify whose operation is to be performed.
        # Value 	Explanation
        # OFPFC_ADD 	Adds new flow entries.
        # OFPFC_MODIFY 	Updates flow entries.
        # OFPFC_MODIFY_STRICT 	Update strictly matched flow entries
        # OFPFC_DELETE 	Deletes flow entries.
        # OFPFC_DELETE_STRICT 	Deletes strictly matched flow entries.

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

    #TODO: Final Questions - What is the use on the flood? Why do wee need the mac address of a device?
    # in case of miss we flood all other ports supposedly to check if we have an output port associated with it in the openflow table
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

    #TODO: Final Questions - What is the ARP protocol? 
    # Address Resolution Protocol (ARP) is a protocol or procedure that connects an ever-changing Internet Protocol (IP) address to a fixed physical machine address, also known as a media access control (MAC) address, in a local-area network (LAN). 
    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        """
        This forwards the ARP message, to obtain the MAC address, depending if it is now different acctions are taken. 
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

            #TODO: Final Questions - What is the eth_dst parameter in the match?
            # port associated with the destinato port to output the packet 
            #TODO: Final Questions - What other parameters could we try to match? What is a wildcard?
            # need research

            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
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
            return True

    def send_group_mod(self, datapath):
        """
        This function creates the group rule for the corresponding datapath
        :type datapath: ryu.controller.controller.Datapath
        :return: None 
        :rtype:  None 
        """
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # Multi Path Transmission
	    # It behaves as a load balancer for the topology of the workshop

        # TODO: Complete switch one
        '''
        #switch 4
        if datapath.id == 4:
            self.send_group_mod(datapath)
            actions = [parser.OFPActionGroup(group_id=50)]
            match = parser.OFPMatch(in_port=2)
            # self.add_flow(datapath, 10, match, actions)
            # # entry 2
            # actions = [parser.OFPActionGroup(group_id=51)]
            # match = parser.OFPMatch(in_port=3)
            # self.add_flow(datapath, 10, match, actions)
        '''

        '''
        # LB_WEIGHT1 = 50 #percentage
        # LB_WEIGHT2 = 50 #percentage

        port_1 = 3
        actions_1 = [ofp_parser.OFPActionOutput(port_1)]

        port_2 = 2
        actions_2 = [ofp_parser.OFPActionOutput(port_2)]

        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = [
            ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
            ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        group_id = 50
        req = ofp_parser.OFPGroupMod(
            datapath, ofp.OFPFC_ADD,
            ofp.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)
        '''
        port_1 = 3
        queue_1 = ofp_parser.OFPActionSetQueue(0)
        actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]

        port_2 = 2
        queue_2 = ofp_parser.OFPActionSetQueue(1)
        actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]

        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = [
            ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
            ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        group_id = 50
        req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)
        
    #TODO: Final Questions - What is the event here and what is the difference with the CONFIG_DISPATCHER in the previous function?
    # switch feature for the ryu controller.. need more research
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Called every time, when the controller receives a PACKET_IN message
        :type ev: ryu.controller.ofp_event.EventOFPPacketIn
        :return: None
        :rtype: None
        """	
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
        

        # create a Packet object out of the payload
        # TODO: 1) Create a Packet from the message data
        #msg data parsed
        pkt = packet.Packet(msg.data)

        #TODO: Final Questions - Why do we need obtain the information for four different protocols?
        #You can create a Packet class instance with the received raw data. Then the packet library parses the data and creates protocol class instances included the data. The packet class ’protocols’ has the protocol class instances. to be able to decode/parse() the data and encode/serialize() the data
        # also we are doing load balancing on layer 4 and to get destination and source IP and match protocol to process them
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        #arp.arp_ID
        arp_pkt = pkt.get_protocol(arp.arp)
        # dst = eth.dst
        # src = eth.src

        # print(("Ehternet packet in %s %s %s %s", dpid, src, dst, in_port))
        # print(("IP packet in %s %s %s %s", dpid, ip_pkt.src, ip_pkt.dst, in_port))

        

        # Don't do anything with IPV6 packets.
        # parser for the decoding the packet.. serialize() is to encode
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
            self.add_flow(datapath, match, actions)
            return 

        # ARP Protcol
        if isinstance(arp_pkt, arp.arp):
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return
	    # Complete ARP protocol
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        # This is the focus of this workshop -> Process the IPv4 message
        if isinstance(ip_pkt, ipv4.ipv4):
            # find the switch in the mac_to_port table
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table is None:
                self.logger.info("Dpid is not in mac_to_port")
                return
            # source and destination mac address of the ethernet packet
            dst = eth.dst
            src = eth.src

            out_port = None
            # "Known destination MAC address" -> We have seen this before
            if dst in mac_to_port_table:
                #TODO: Final Questions - Why do we need the foolowing special cases?
                # to establish packet flow
                if dpid == 1 and in_port == 1:
                    # This is the special case for host 1 only do create create the group the first time
                    if self.FLAGS is True:
                        self.send_group_mod(datapath)
                        self.FLAGS = False
                    #TODO: Final Questions - Where is this group defined?
                    #send group modification function
                    # research more
                    actions = [parser.OFPActionGroup(group_id=7)]
                    #TODO: Final Questions - Why do we need to create groups and flows in different steps?
                    # research more.. but has to do with buckets design
                    match = parser.OFPMatch(in_port=in_port,
                                            eth_type=eth.ethertype,
                                            ipv4_src=ip_pkt.src)
                    self.add_flow(datapath, match, actions)
                    # asign output at 2
                    self.send_packet_out(datapath, msg.buffer_id,
                                         in_port, 2, msg.data)
                else:
                    #Normal flows
                    # "Install a flow to avoid packet_in next time">
                    out_port = mac_to_port_table[eth.dst]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                                            eth_type=eth.ethertype)
                   #Add the flow to the switch
                    self.add_flow(datapath, match, actions)
                    #Send packet to its destination
                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port, msg.data)
            # "Unknown destination MAC address"
            else:
                # MAC is not Known
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    # we don't know anything, so flood the network 
                    self.flood(msg)


    #TODO: Final Questions - What do you think this decorator could be useful for?
    #@set_ev_cls(event.EventSwitchEnter) is an event listener to manage events and handlers
    #the ’set_ev_cls’ decorator. This decorator tells Ryu when the decorated function
    # should be called.
    # The first argument of the decorator indicates which type of event this function should be called for. As you might
    # expect, every time Ryu gets a packet_in message, this function is called.
    # The second argument indicates the state of the switch. You probably want to ignore packet_in messages before the
    # negotiation between Ryu and the switch is finished. Using ’MAIN_DISPATCHER’ as the second argument means
    # this function is called only after the negotiation completes.
    # they are useful for adding functionality while handling events
    # set_ev_cls specifies the event class supporting the recieved message the state of the openflow switch argument 

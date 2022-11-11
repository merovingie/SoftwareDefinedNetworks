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

# Mininet topology for this app
# sudo mn --controller=remote,ip=127.0.0.1 --mac  --switch=ovsk,protocols=OpenFlow13 --topo=linear,4

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.controller import dpset

from ryu import cfg

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host

from ryu.lib import hub

import igraph as ig

from collections import deque, defaultdict
from operator import attrgetter
import copy
import json

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
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
        self.strategy: str = CONF.strategy
        self.T1: int = CONF.T1
        self.T2: int = CONF.T2
        self.S1: int = CONF.S1
        self.T3: int = (CONF.T1 - 3)

        self.mac_to_port = {}
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.topo_raw_hosts = []
        self.switch_entered = []
        self.datapaths = {}

        self.topology_api_app = self

        self.dpset = kwargs['dpset']

        self.discover_thread = hub.spawn(self._discover)

        self.arp_table = {}     # can be built from topology discovery
        self.hosts_to_switch = {}   # that's done via topology discovery

        self.graph = ig.Graph(directed=True)

        # added stuff
        self.samples = []
        self.average_bps_links = {}
        self.link_stats = {}
        self.ip_stats = {}
        self.rebalancing = False
        self.BYTES_PER_MEGABIT = 125000

        print('monitoring every', self.T1, 'seconds')
        print('rebalancing every', self.T2, 'seconds')
        print('disovering every', self.T3, 'seconds')
        print(f'keeping {self.S1} bw samples per link')

        # configure link parameters
        self.link_config = {}
        self.parse_link_config('link_config.json', self.link_config)

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

    def _get_hwaddr(self, dpid, port_no):
        mac_for_port = self.dpset.get_port(dpid, port_no).hw_addr
        print('mac address for Port {} on switch {} is {}'.format(port_no, dpid, mac_for_port))
        return mac_for_port

    def _discover(self):
        while True:
            # get switches
            self.topo_raw_switches = copy.copy(get_switch(self, None))
            self.switches_entered = [switch.dp.id for switch in self.topo_raw_switches]
            print("Swtiches:\n", self.switches_entered)
            for switch in self.topo_raw_switches:
                try:
                    self.graph.vs.find(str(switch.dp.id))
                except:
                    print("switch {} doesnt exist in graph".format(switch.dp.id))
                    self.graph.add_vertex(str(switch.dp.id))
                    print("Graph\n", self.graph)
                    if not switch.dp.id in self.datapaths:
                        self.logger.info('register datapath: %016x', switch.dp.id)
                        self.datapaths[switch.dp.id] = switch.dp
                        print("datapaths ", self.datapaths)

            # get links
            self.topo_raw_links = copy.copy(get_link(self, None))
            links = [(link.src.dpid, link.dst.dpid, {'port_out': link.src.port_no}, {'port_in': link.dst.port_no}) for link in self.topo_raw_links]
            print("Links:\n", links)
            for link in self.topo_raw_links:
                try:
                    bw = self.link_config[str(link.src.port_no) + str(link.dst.port_no)]["bw"]
                    lat = self.link_config[str(link.src.port_no) + str(link.dst.port_no)]["lat"]
                except KeyError as e:
                    bw = 100
                    lat = 2


                try:
                    self.graph.get_eid(str(link.src.dpid), str(link.dst.dpid))
                except:
                    print("link between swtich {} and switch {} doesnt exist in graph".format(str(link.src.dpid), str(link.dst.dpid)))
                    self.graph.add_edge(str(link.src.dpid), str(link.dst.dpid),
                                        src_dpid=link.src.dpid,
                                        dst_dpid=link.dst.dpid,
                                        src_port=link.src.port_no,
                                        dst_port=link.dst.port_no,
                                        bw=bw,
                                        lat=lat,
                                        estimated_bw=bw,
                                        last_bws=deque(maxlen=self.S1),
                                        last_num_bytes=0)
                    print("Graph\n", self.graph)

            # get hosts
            self.topo_raw_hosts = copy.copy(get_host(self.topology_api_app, None))
            for h in self.topo_raw_hosts:
                print("hosts in packet handler: ", h)
                mac = h.mac
                switch = h.port.dpid
                port = h.port.port_no
                if len(h.ipv4) > 0:
                    ip = h.ipv4[0]
                    print("IP HOST ", ip)
                    if ip not in self.arp_table:
                        print("{} added to ARP TABLE".format(ip))
                        self.arp_table[ip] = mac
                print("mac", mac)
                print("Switch ", switch)
                print("Port No. ", port)
                port_mac = self._get_hwaddr(switch, port)

                if mac not in self.hosts_to_switch:
                    self.hosts_to_switch[mac] = switch

                datapath = self.datapaths[switch]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                actions = [parser.OFPActionOutput(port)]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        eth_src=mac, eth_dst=port_mac)
                self.add_flow(datapath, 1, match, actions)

            hub.sleep(self.T3)

        # This event is fired when a switch leaves the topo. i.e. fails.
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def _handler_switch_leave(self, ev):
        # self.logger.info("Not tracking Switches, switch leaved.")
        print("switch left.", ev.switch.dp.id)
        self.graph.delete_vertices(str(ev.switch.dp.id))
        print("Graph\n", self.graph)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        address = ev.msg.datapath.address
        print("IP ", address)
        dpid = ev.msg.datapath.id
        print("swtich ID ", dpid)
        switches = self.dpset.get_all()

        # this part isn't working
        mac_addresses = [(s[0], s[1].ports[ofproto_v1_3.OFPP_LOCAL].hw_addr)for s in switches]
        print("mac_addresses {}".format(mac_addresses))

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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
        print("Mod reply ", mod)
        datapath.send_msg(mod)

    def arp_process(self, datapath, eth, a, in_port):
        r = self.arp_table.get(a.dst_ip)
        if r:
            self.logger.info("Matched MAC %s ", r)
            arp_resp = packet.Packet()
            arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                  dst=eth.src, src=r))
            arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                  src_mac=r, src_ip=a.dst_ip,
                                  dst_mac=a.src_mac,
                                  dst_ip=a.src_ip))

            arp_resp.serialize()
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
            datapath.send_msg(out)
            self.logger.info("Proxied ARP Response packet")



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        out_port = None
        actions = []
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src



        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("***PacketIn***: Switch number %s Source mac %s Destination mac %s in_port %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        print("mac_to_port ", self.mac_to_port)
        print("Arp Table ", self.arp_table)
        print("Hosts_to_Switch ", self.hosts_to_switch)

        try:
            src_switch_dpid = self.hosts_to_switch[src]
            dst_switch_dpid = self.hosts_to_switch[dst]
            src_port = self.mac_to_port[src_switch_dpid][src]
            dst_port = self.mac_to_port[dst_switch_dpid][dst]
            config_key = str(src_port) + str(dst_port)
            config_cap = self.link_config[config_key]['bw'] if config_key in self.link_config else 100
        except:
            pass

        # Check whether is it arp packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # self.logger.info("Received *** ARP Packet *** on Switch %s Source Mac %s Destination Mac %s ", dpid, src, dst)
            a = pkt.get_protocol(arp.arp)
            self.arp_process(datapath, eth, a, in_port)
            return

        # no ARP flooding
        # avoid flooding if learnt
        try:
            dst_switch_dpid = self.hosts_to_switch[dst]
            dst_switch_vid = self.graph.vs.find(name=str(dst_switch_dpid)).index
            start_switch_vid = self.graph.vs.find(name=str(dpid)).index
        except:
            pass

        if self.strategy == "shortest_path":
            print('finding shortest_path')
            try:
                path = self.graph.get_shortest_paths(str(dpid), str(dst_switch_dpid), output='epath')[0]
            except:
                pass
        elif self.strategy == "widest_path":
            try:
                path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='bw', link_config_cap=config_cap)
            except:
                pass
        elif self.strategy == "proactive":
            try:
                path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='estimated_bw', link_config_cap=config_cap)
                print('using proactive rules. found path of bw: ', path_bw)
                if path_bw <= 0:
                    print('effective bandwidth zero, reverting to original rules')
                    path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='bw', link_config_cap=config_cap)
            except:
                pass
        else:
            print('invalid strategy parameters')
            exit()
        try:
            if len(path) != 0:
                print('found path:', )
                for p in path:
                    print(self.graph.es[p]['src_dpid'])
                out_port = self.graph.es[path[0]]['src_port']
                actions = [parser.OFPActionOutput(out_port)]
            else:
                print('same switch')
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]
        except:
            pass

            # # out_port = ofproto.OFPP_FLOOD
            # # print("no outport")
            # out_port = None
            # actions =[]

        # actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # added stuff
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

    def remove_table_flows(self, datapath, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod

    def remove_flows(self, datapath):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath,
                                           empty_match, instructions)
        print('deleting all flows from switch', datapath.id, 'return', flow_mod)
        datapath.send_msg(flow_mod)

    @set_ev_cls([event.EventLinkAdd])
    def _link_Add(self, ev):
        print("Link Added:", ev.link.src.dpid, ev.link.src.port_no, ev.link.dst.dpid, ev.link.dst.port_no)
        link = ev.link
        src = ev.link.src.dpid
        print(" ADD link with src ", src)
        dst = ev.link.dst.dpid
        print(" ADD link with dst ", dst)

        # code to add link
        try:
            bw = self.link_config[str(ev.link.src.port_no) + str(ev.link.dst.port_no)]["bw"]
            lat = self.link_config[str(ev.link.src.port_no) + str(ev.link.dst.port_no)]["lat"]
        except KeyError as e:
            bw = 100
            lat = 2

        bw *= self.BYTES_PER_MEGABIT * self.T1

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

        print('+++ removing all flows from switchs +++')
        for switch in self.switches_entered:
            self.delete_flow(self.datapaths[switch])

        print(self.graph)

        for h in self.topo_raw_hosts:
            print('+++ adding hosts after deleting links +++')
            print("hosts in packet handler: ", h)
            mac = h.mac
            switch = h.port.dpid
            port = h.port.port_no
            print("mac ", mac)
            print("Switch ", switch)
            print("Port No. ", port)
            port_mac = self._get_hwaddr(switch, port)

            datapath = self.datapaths[switch]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(port)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    eth_src=mac, eth_dst=port_mac)
            mod = self.add_flow(datapath, 1, match, actions)
            print('reply after trying to delete link and then add hosts again to switch\n', mod)

    @set_ev_cls(event.EventLinkDelete)
    def _link_Delete(self, ev):
        link = ev.link
        src = ev.link.src.dpid
        print(" Delete link with src ",src)
        dst = ev.link.dst.dpid
        print(" Delete link with dst ", dst)

        # code to remove link
        try:
            link_to_delete = self.graph.get_eid(str(ev.link.src.dpid), str(ev.link.dst.dpid))
            print("link to delete EID ", link_to_delete)
            self.graph.delete_edges(link_to_delete)
            # self.delete_flow_link(self.datapaths[dst], link.dst.port_no)



            link_to_delete = self.graph.get_eid(str(ev.link.dst.dpid), str(ev.link.src.dpid))
            print("link to delete EID ", link_to_delete)
            self.graph.delete_edges(link_to_delete)
            # self.delete_flow_link(self.datapaths[src], link.src.port_no)

            print('+++ removing all flows from switchs +++')
            for switch in self.switches_entered:
                self.delete_flow(self.datapaths[switch])

            print(self.graph)

        except:
            pass

        for h in self.topo_raw_hosts:
            print('+++ adding hosts after deleting links +++')
            print("hosts in packet handler: ", h)
            mac = h.mac
            switch = h.port.dpid
            port = h.port.port_no
            print("mac ", mac)
            print("Switch ", switch)
            print("Port No. ", port)
            port_mac = self._get_hwaddr(switch, port)

            datapath = self.datapaths[switch]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(port)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    eth_src=mac, eth_dst=port_mac)
            mod = self.add_flow(datapath, 1, match, actions)
            print('reply after trying to delete link and then add hosts again to switch\n', mod)

    def delete_flow_link(self, datapath, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("deleting rule from switch {} for port {}".format(datapath.id, dst_port))
        print("type of", type(dst_port))
        match = parser.OFPMatch(in_port=dst_port)
        mod = parser.OFPFlowMod(
            datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            priority=1, match=match)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id]:
            print("this is mac_to_port Dst ", dst)
            print('deleting flows for dst:', dst, ' on datapath:', datapath.id)
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)
            print("deleting rules reply", mod)

    def widest_dijkstra(self, g, s, bw='bw', link_config_cap=100):
        previous = {}  # previous hops
        cap = {}  # capacities between nodes
        T = set()
        V = set(range(g.vcount()))  # Initially set of all nodes
        T.add(s)
        V.remove(s)
        cap[s] = float(link_config_cap * self.BYTES_PER_MEGABIT * self.T1) # links from host to switch are always bw 100 but not included in our graph
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

    def widest_path(self, s, d, bw='bw', link_config_cap=100):
        cap, prev = self.widest_dijkstra(self.graph, s, bw, link_config_cap)
        return self.get_edges_from_prev(self.graph, s, d, prev), cap[d]



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
        for stat in sorted([flow for flow in body if
                            flow.priority == 1 and 'in_port' in flow.match and 'eth_dst' in flow.match and 'eth_src' in flow.match],
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
            if self.link_stats.get(dst) is None:
                self.link_stats[dst] = {}

            if self.link_stats[src].get(dst) is None:
                self.link_stats[src][dst] = dict(src=src, dst=dst,
                                                 packets=0, last_byte_count=0,
                                                 prev_counts=deque(maxlen=self.S1),
                                                 avg_bytes=0)
            if self.link_stats[dst].get(src) is None:
                self.link_stats[dst][src] = dict(src=dst, dst=src,
                                                 packets=0, last_byte_count=0,
                                                 prev_counts=deque(maxlen=self.S1),
                                                 avg_bytes=0)

            stats = self.link_stats[src][dst]
            stats['packets'] = stat.packet_count
            curr_bytes = max(0, stat.byte_count - stats['last_byte_count'])
            stats['last_byte_count'] = curr_bytes
            stats['prev_counts'].append(curr_bytes)
            stats['avg_bytes'] = sum(stats['prev_counts']) / self.S1
            # print(f'stats saved: {stats}')
            stats2 = self.link_stats[dst][src]
            stats2['packets'] = stat.packet_count
            curr_bytes = max(0, stat.byte_count - stats2['last_byte_count'])
            stats2['last_byte_count'] = curr_bytes
            stats2['prev_counts'].append(curr_bytes)
            stats2['avg_bytes'] = sum(stats2['prev_counts']) / self.S1

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
        with open('switch_byte_counts.txt', 'a') as file:
            for stat in sorted(body, key=attrgetter('port_no')):
                port_byte_counts[stat.port_no] += stat.tx_bytes
                self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                                 ev.msg.datapath.id, stat.port_no,
                                 stat.rx_dropped, stat.rx_bytes, stat.rx_errors,
                                 stat.tx_dropped, stat.tx_bytes, stat.tx_errors)
                file.write(f'{ev.msg.datapath.id} {stat.rx_bytes}\r\n')

        for port in port_byte_counts:
            byte_count = port_byte_counts[port]
            src_vid = self.graph.vs["name"].index((str(ev.msg.datapath.id)))
            try:
                edge = self.graph.es.find(_source=src_vid, src_port=port)
            except ValueError as e:
                pass
            except KeyError as e:
                pass
            else:
                last_bw_used = (byte_count - edge['last_num_bytes'])
                edge['last_bws'].append(max(edge['bw'] - last_bw_used, 0))
                edge['estimated_bw'] = sum(edge['last_bws']) / self.S1
                edge['last_num_bytes'] = byte_count
    # get all flows for distribution
    def get_flows(self, epath, src, dst, info, src_ip, dst_ip):
        flows = []

        # append flow for src
        dpid = self.hosts_to_switch[src]
        in_port = self.mac_to_port[dpid][src]

        if len(epath) == 0:
            if self.hosts_to_switch[dst] != dpid:
                return None

            out_port = self.mac_to_port[dpid][dst]
            flows.append(dict(dpid=dpid, in_port=in_port, out_port=out_port, eth_dst=dst, eth_src=src, ip_src=src_ip, ip_dst=dst_ip))

            return flows

        out_port = self.graph.es[epath[0]]['src_port']
        flows.append(dict(dpid=dpid, in_port=in_port, out_port=out_port, eth_dst=dst, eth_src=src, ip_src=src_ip, ip_dst=dst_ip))

        for i in range(len(epath) - 1):
            es = self.graph.es[epath[i]]
            next_es = self.graph.es[epath[i + 1]]

            # flow parameters
            dpid = es['dst_dpid']
            in_port = es['dst_port']
            out_port = next_es['src_port']

            # append the flow to be added later
            flows.append(dict(dpid=dpid, in_port=in_port, out_port=out_port, eth_dst=dst, eth_src=src, ip_src=src_ip, ip_dst=dst_ip))

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
        flows.append(dict(dpid=dpid, in_port=in_port, out_port=out_port, eth_dst=dst, eth_src=src, ip_src=src_ip, ip_dst=dst_ip))

        self.bw_print(epath[-1])
        updated_bw = last_es['estimated_bw'] - info['avg_bytes']
        last_es['estimated_bw'] = max(0, updated_bw)
        self.bw_print(epath[-1])
        print("get flows before return: ", flows)
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

        info_list = sorted(info_list, key=lambda info: info['packets'], reverse=True)

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
            src_port = self.mac_to_port[src_switch_dpid][src]
            dst_port = self.mac_to_port[dst_switch_dpid][dst]
            config_key = str(src_port) + str(dst_port)
            config_cap = self.link_config[config_key]['bw'] if config_key in self.link_config else 100

            cap, prev = self.widest_dijkstra(self.graph, src_vid, bw='estimated_bw', link_config_cap=config_cap)
            if cap[dst_vid] > 0:
                print('finding edges from switch_dpid', src_switch_dpid, 'to switch_dpid', dst_switch_dpid)
                epath = self.get_edges_from_prev(self.graph, src_vid, dst_vid, prev)
                print('\tpath(%d):' % (len(epath)))
                if len(epath) != 0:
                    for eid in epath:
                        print(self.graph.es[eid]['src_dpid'], )
                    print(self.graph.es[epath[-1]]['dst_dpid'])
                else:
                    print(self.hosts_to_switch[src])

                new_flows = self.get_flows(epath, src, dst, info)

                if new_flows is None:
                    print('some hosts appeared to be unreachable, not rebalancing')
                    # restore old estimates
                    self.graph.es['estimated_bw'] = estimates
                    return
                flows += new_flows
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
            print('\tin_port', flow['in_port'], 'eth_src', flow['eth_src'], 'eth_dst', flow['eth_dst'], 'out_port',
                  flow['out_port'])
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
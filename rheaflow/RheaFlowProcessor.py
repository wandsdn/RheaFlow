#!/usr/bin/env python
#-*- coding:utf-8 -*-
#
# Copyright (C) 2016 Oladimeji Fayomi, University of Waikato.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Name: RheaFlowProcessor.py
# Author : Oladimeji Fayomi
# Created : 14 February 2016
# Last Modified :
# Version : 1.0
# Description: Converts Routes to OF messages, processes OF messages received
#              from switches

import logging
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet.arp import arp, ARP_REQUEST, ARP_REPLY
from ryu.lib.packet import packet
from ryu.lib.packet.icmp import icmp, ICMP_ECHO_REQUEST
from ryu.lib.packet.icmpv6 import icmpv6
from log import log
from RheaFastpath import MetaVLAN
from netaddr import IPAddress, IPNetwork

RFVS_PREFIX = 0x72667673
vs_id = '7266767372667673'
is_rfvs = lambda dp_id: not ((dp_id >> 32) ^ RFVS_PREFIX)
fp_priority = 36000
cookie = cookie_mask = 0
table_id = 0
idle_timeout = hard_timeout = 0


class RheaFlowProcessor(object):

    OFP_VERSIONs = [ofproto.OFP_VERSION]

    def __init__(self, switches, *args, **kwargs):
        self._switches = switches
        self._datapaths = self._switches.dps
        self.labeller = MetaVLAN()
        self.HostonDP = {}
        self.routetable = {}
        self.cookie_counter = 1

    def update_route_table(self, route, cookie):
        '''
           Uses the the cookie id of a flow to map
           it to the route that generated the flow.
        '''
        if route not in self.routetable:
            self.routetable[route] = cookie

    def clear_flows(self, datapath):
        ''' Delete existing rules on the datapath'''
        ofp_parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        match = ofp_parser.OFPMatch()
        inst = []
        msg = ofp_parser.OFPFlowMod(datapath=datapath, table_id=ofp.OFPTT_ALL,
                                    command=ofp.OFPFC_DELETE,
                                    out_port=ofp.OFPP_ANY,
                                    out_group=ofp.OFPG_ANY,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(msg)

    def decrement_ip_ttl(self, parser, actions=None, decrement_ttl=False):
        '''
            Decrement TTL for flows added to forward IP packets
            between two different networks.
        '''
        if actions is None:
            actions = []

        if decrement_ttl is True:
            actions = [parser.OFPActionDecNwTtl()] + actions

        return actions

    def vs_fastpath_flows(self, label, vs_fastpath_port, vs_port):
        vswitch = self._switches._get_switch(str_to_dpid(vs_id))
        msgs = []
        dp = vswitch.dp
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        cookie = cookie_mask = 0
        table_id = 0
        buffer_id = ofp.OFP_NO_BUFFER
        fp_priority = 36000
        match = ofp_parser.OFPMatch(in_port=vs_fastpath_port,
                                    vlan_vid=(label | ofproto.OFPVID_PRESENT))
        actions = self.labeller.pop_action_meta(ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=vs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask, table_id,
                                          ofp.OFPFC_ADD, idle_timeout,
                                          hard_timeout, fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=vs_port)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=vs_fastpath_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask, table_id,
                                          ofp.OFPFC_ADD, idle_timeout,
                                          hard_timeout, fp_priority,
                                          buffer_id, ofp.OFPP_ANY,
                                          ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=vs_port, eth_type=0x0806, arp_op=1)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=vs_fastpath_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask, table_id,
                                          ofp.OFPFC_ADD, idle_timeout,
                                          hard_timeout, fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        self.send_msgs(dp, msgs)

    def generate_ip6_link_local(self, mac):
        '''
            Generate the IPv6 link-local address of the virtual ports on dp0
            since we know their MAC addresses.
        '''
        macstrip = int(mac.translate(None, ' .:-'), 16)
        prefix1 = macstrip >> 24 & 0xff
        prefix2 = macstrip >> 32 & 0xffff ^ 0x0200
        suffix1 = macstrip >> 16 & 0xff
        suffix2 = macstrip & 0xffff

        return 'fe80::{:04x}:{:02x}ff:fe{:02x}:{:04x}'.format(prefix2, prefix1,
                                                              suffix1, suffix2)

    def ingress_isl_flows(self, datapath, label, port_no, interswitch_links):
        isl_priority = 36000
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        table_id = 0
        msgs = []
        buffer_id = ofp.OFP_NO_BUFFER
        for dp_isl_port in interswitch_links:
            match = ofp_parser.OFPMatch(in_port=dp_isl_port,
                                        vlan_vid=(label | ofproto.OFPVID_PRESENT))
            actions = self.labeller.pop_action_meta(ofp_parser, None)
            actions += [ofp_parser.OFPActionOutput(port=port_no)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                              table_id, ofp.OFPFC_ADD,
                                              idle_timeout, hard_timeout,
                                              isl_priority, buffer_id,
                                              ofp.OFPP_ANY, ofp.OFPG_ANY,
                                              ofp.OFPFF_SEND_FLOW_REM,
                                              match, inst))
        self.send_msgs(datapath, msgs)

    def egress_isl_flows(self, datapath, label, ingress_port, egress_port):
        isl_priority = 36000
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        table_id = 0
        buffer_id = ofp.OFP_NO_BUFFER
        msgs = []
        match = ofp_parser.OFPMatch(in_port=ingress_port,
                                    vlan_vid=(label | ofproto.OFPVID_PRESENT))
        actions = [ofp_parser.OFPActionOutput(port=egress_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          isl_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=egress_port,
                                    vlan_vid=(label | ofproto.OFPVID_PRESENT))
        actions = [ofp_parser.OFPActionOutput(port=ingress_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          isl_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        self.send_msgs(datapath, msgs)

    def fastpath_flows(self, datapath, label, port_no, dp_fs_port,
                       vs_port_hw_addr):
        fp_priority = 36000
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        table_id = 0
        msgs = []
        buffer_id = ofp.OFP_NO_BUFFER
        match = ofp_parser.OFPMatch(in_port=dp_fs_port,
                                    vlan_vid=(label | ofproto.OFPVID_PRESENT))
        actions = self.labeller.pop_action_meta(ofp_parser, None)
        actions += [ofp_parser.OFPActionOutput(port=port_no)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=port_no,
                                    eth_dst=vs_port_hw_addr)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        ''' IPv6 flow rules '''
        match = ofp_parser.OFPMatch(in_port=port_no, eth_type=0x86DD,
                                    ip_proto=58)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=port_no, ipv6_dst='ff02::2',
                                    eth_dst='33:33:00:00:00:02',
                                    eth_type=0x86DD)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=port_no, ipv6_dst='ff02::16',
                                    eth_dst='33:33:00:00:00:16',
                                    eth_type=0x86DD)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        vs_ip6_ll = self.generate_ip6_link_local(vs_port_hw_addr)
        match = ofp_parser.OFPMatch(in_port=port_no,
                                    eth_dst=vs_port_hw_addr,
                                    ipv6_dst=vs_ip6_ll,
                                    eth_type=0x86DD)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        ''' IPv6 Multicast '''
        s_node_mcast = IPNetwork('ff02::1:ff00:0/104')
        match = ofp_parser.OFPMatch(in_port=port_no,
                                    ipv6_dst=(str(s_node_mcast.ip),
                                              str(s_node_mcast.netmask)),
                                    eth_type=0x86DD)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        node_mcast = IPNetwork('ff02::2:ff00:0/104')
        match = ofp_parser.OFPMatch(in_port=port_no,
                                    ipv6_dst=(str(node_mcast.ip),
                                              str(node_mcast.netmask)),
                                    eth_type=0x86DD)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        match = ofp_parser.OFPMatch(in_port=port_no, eth_type=0x0806,
                                    arp_op=1)
        actions = self.labeller.push_action_meta(label, ofp_parser)
        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                          table_id, ofp.OFPFC_ADD,
                                          idle_timeout, hard_timeout,
                                          fp_priority, buffer_id,
                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          ofp.OFPFF_SEND_FLOW_REM,
                                          match, inst))
        self.send_msgs(datapath, msgs)

    def create_initial_flow(self, datapath, vs_port_hw_addr=None, dp_port=None):
        '''
            Installs initial flow rules on the datapaths connected to the controller,
            if FastPath is not setup.
        '''
        ofp = datapath.ofproto
        datapath_id = datapath.id
        ofp_parser = datapath.ofproto_parser
        msgs = []
        if not is_rfvs(datapath_id):
            cookie = cookie_mask = 0
            table_id = 0
            idle_timeout = hard_timeout = 0
            priority = 11
            if (dp_port is not None):
                buffer_id = ofp.OFP_NO_BUFFER
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            eth_dst=vs_port_hw_addr)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                      ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            eth_dst=vs_port_hw_addr,
                                            eth_type=0x0800)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            eth_dst=vs_port_hw_addr,
                                            eth_type=0x86DD)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            eth_type=0x86DD,
                                            ip_proto=58)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            ipv6_dst='ff02::2',
                                            eth_dst='33:33:00:00:00:02',
                                            eth_type=0x86DD)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            ipv6_dst='ff02::16',
                                            eth_dst='33:33:00:00:00:16',
                                            eth_type=0x86DD)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                vs_ip6_ll = self.generate_ip6_link_local(vs_port_hw_addr)
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            eth_dst=vs_port_hw_addr,
                                            ipv6_dst=vs_ip6_ll,
                                            eth_type=0x86DD)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                s_node_mcast = IPNetwork('ff02::1:ff00:0/104')
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            ipv6_dst=(str(s_node_mcast.ip),
                                                      str(s_node_mcast.netmask)),
                                            eth_type=0x86DD)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                node_mcast = IPNetwork('ff02::2:ff00:0/104')
                match = ofp_parser.OFPMatch(in_port=dp_port,
                                            ipv6_dst=(str(node_mcast.ip),
                                                      str(node_mcast.netmask)),
                                            eth_type=0x86DD)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                match = ofp_parser.OFPMatch(in_port=dp_port, ip_proto=1,
                                            eth_dst=vs_port_hw_addr,
                                            eth_type=0x0800)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))

                priority = 32800
                match = ofp_parser.OFPMatch(in_port=dp_port, eth_type=0x0806)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))
                priority = 0
                buffer_id = ofp.OFP_NO_BUFFER
                match = ofp_parser.OFPMatch(None)
                actions = []
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                         actions)]
                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                  table_id, ofp.OFPFC_ADD,
                                                  idle_timeout, hard_timeout,
                                                  priority, buffer_id,
                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                  match, inst))

                self.send_msgs(datapath, msgs)

        else:
            cookie = cookie_mask = 0
            table_id = 0
            msgs = []
            idle_timeout = hard_timeout = 0
            priority = 1
            buffer_id = ofp.OFP_NO_BUFFER
            match = ofp_parser.OFPMatch(None)
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                              table_id, ofp.OFPFC_ADD,
                                              idle_timeout, hard_timeout,
                                              priority, buffer_id,
                                              ofp.OFPP_ANY, ofp.OFPG_ANY,
                                              ofp.OFPFF_SEND_FLOW_REM,
                                              match, inst))
            ''' Set a higher priority for ARP on dp0.'''
            arp_priority = 34000
            match = ofp_parser.OFPMatch(eth_type=0x0806)
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                              table_id, ofp.OFPFC_ADD,
                                              idle_timeout, hard_timeout,
                                              arp_priority, buffer_id,
                                              ofp.OFPP_ANY, ofp.OFPG_ANY,
                                              ofp.OFPFF_SEND_FLOW_REM,
                                              match, inst))
            self.send_msgs(datapath, msgs)

    def find_with_ifindex(self, ifindex, iftable):
        ''' Find an interface in the interface table.'''
        for interface in iftable:
            if ifindex in interface.itervalues():
                return interface
        return None

    def find_with_mac(self, mac, iftable):
        ''' Find an interface using MAC address in
            the interface table.
        '''
        for iface in iftable:
            if mac in iface.itervalues():
                return iface
        return None

    def find_with_ip(self, ipaddr, iftable):
        ''' Find an interface with IP address in the
            interface table.
        '''
        ipnet = IPNetwork(ipaddr)
        for iface in iftable:
            address_list = iface['IP-Addresses']
            for addr in address_list:
                address, mask = addr
                addrnet = IPNetwork(address)
                if ipnet.ip == addrnet.ip:
                    return iface
        return None

    def delete_flows(self, route, map_table, iftable, neigh_table,
                     vsif_to_ofp, **next_hop):
        ''' Delete flow entries for routes removed. '''
        if 'host' in next_hop:
            for dpid, dp in self._datapaths.items():
                if not is_rfvs(dpid):
                    ofp = dp.ofproto
                    ofp_parser = dp.ofproto_parser
                    table_id = 0
                    msgs = []
                    buffer_id = ofp.OFP_NO_BUFFER
                    idle_timeout = hard_timeout = 0
                    priority = 38000
                    network = route[0]
                    netmask = str(route[2])
                    ip = IPNetwork(network+'/'+netmask)
                    mask = str(ip.netmask)
                    host = next_hop['host']
                    vs_ifindex = host['ifindex']
                    vs_interface = self.find_with_ifindex(vs_ifindex, iftable)
                    if vs_interface:
                        vs_int_mac = vs_interface['mac-address']
                        vs_int_name = vs_interface['ifname']
                    if vs_ifindex in vsif_to_ofp:
                        vs_ofp_no = vsif_to_ofp[vs_ifindex]
                        vs_dp_map = map_table.vs_port_to_dp_port(vs_int_name,
                                                                 vs_ofp_no,
                                                                 vs_int_mac)
                        if vs_dp_map:
                            dp_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            if dp_id == dpid_to_str(dpid):
                                for port in dp.ports:
                                    port_name = dp.ports[port].name
                                    port_hw_addr = dp.ports[port].hw_addr
                                    port_no = dp.ports[port].port_no
                                    dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                             port_no, port_name,
                                                                             port_hw_addr)
                                    if dp_vs_map is None:
                                        pass
                                    else:
                                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                        if ip.version == 4:
                                            if network == '0.0.0.0':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=(network, mask))
                                        else:
                                            if network == '::':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=(network, mask))
                                        inst = []
                                        msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                          table_id, ofp.OFPFC_DELETE,
                                                                          idle_timeout, hard_timeout,
                                                                          priority, buffer_id,
                                                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                          0, match, inst))
                            else:
                                for port in dp.ports:
                                    port_name = dp.ports[port].name
                                    port_hw_addr = dp.ports[port].hw_addr
                                    port_no = dp.ports[port].port_no
                                    dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                             port_no, port_name,
                                                                             port_hw_addr)
                                    if dp_vs_map is None:
                                        pass
                                    else:
                                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                        if ip.version == 4:
                                            if network == '0.0.0.0':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=(network, mask))
                                        else:
                                            if network == '::':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=(network, mask))
                                        inst = []
                                        msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                          table_id, ofp.OFPFC_DELETE,
                                                                          idle_timeout, hard_timeout,
                                                                          priority, buffer_id,
                                                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                          0, match, inst))
                        self.send_msgs(dp, msgs)
                    else:
                        for port in dp.ports:
                            port_name = dp.ports[port].name
                            port_hw_addr = dp.ports[port].hw_addr
                            port_no = dp.ports[port].port_no
                            dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                     port_no,
                                                                     port_name,
                                                                     port_hw_addr)
                            if dp_vs_map is None:
                                pass
                            else:
                                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                if ip.version == 4:
                                    if network == '0.0.0.0':
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x0800,
                                                                    ipv4_dst=network)
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x800,
                                                                    ipv4_dst=(network, mask))
                                else:
                                    if network == '::':
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x86DD,
                                                                    ipv6_dst=network)
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x86DD,
                                                                    ipv6_dst=(network, mask))
                                inst = []
                                msgs.append(ofp_parser.OFPFlowMod(dp, cookie,
                                                                  cookie_mask,
                                                                  table_id,
                                                                  ofp.OFPFC_DELETE,
                                                                  idle_timeout,
                                                                  hard_timeout,
                                                                  priority,
                                                                  buffer_id,
                                                                  ofp.OFPP_ANY,
                                                                  ofp.OFPG_ANY,
                                                                  0, match,
                                                                  inst))
                        self.send_msgs(dp, msgs)
        else:
            table_id = 0
            idle_timeout = hard_timeout = 0
            priority = 38000
            network = route[0]
            netmask = str(route[2])
            ip = IPNetwork(network+'/'+netmask)
            mask = str(ip.netmask)
            vs_interface = next_hop['interface']
            vs_int_name = vs_interface['ifname']
            vs_int_mac = vs_interface['mac-address']
            vs_int_addresses = vs_interface['IP-Addresses']
            vs_int_index = vs_interface['ifindex']
            SameNetwork = False
            for address in vs_int_addresses:
                addr, anetmask = address
                if IPNetwork(addr+'/'+str(anetmask)) == ip:
                    SameNetwork = True
            if vs_int_index in vsif_to_ofp:
                vs_ofp_no = vsif_to_ofp[vs_int_index]
                vs_dp_map = map_table.vs_port_to_dp_port(vs_int_name,
                                                         vs_ofp_no,
                                                         vs_int_mac)
                if vs_dp_map:
                    dp_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                    dp_neighbours = []
                    for neigh in neigh_table:
                        if vs_int_index in neigh.itervalues():
                            dp_neighbours.append(neigh)
                    if SameNetwork is True:
                        switch = self._switches._get_switch(str_to_dpid(dp_id))
                        if switch is not None:
                            msgs = []
                            datapath = switch.dp
                            ofp = datapath.ofproto
                            ofp_parser = datapath.ofproto_parser
                            buffer_id = ofp.OFP_NO_BUFFER
                            for port in datapath.ports:
                                port_no = datapath.ports[port].port_no
                                port_mac = datapath.ports[port].hw_addr
                                port_name = datapath.ports[port].name
                                dp_vs_map = map_table.dp_port_to_vs_port(dp_id,
                                                                         port_no,
                                                                         port_name,
                                                                         port_mac)
                                if port_no == dp_port:
                                    continue

                                if dp_vs_map:
                                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                    if len(dp_neighbours) != 0:
                                        for neigh in dp_neighbours:
                                            host_ip = neigh['ipaddr']
                                            hostip = IPAddress(host_ip)

                                            if (ip.version == 4) and (hostip.version == 4):
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=host_ip)
                                            if (ip.version == 6) and (hostip.version == 6):
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=host_ip)
                                            inst = []
                                            msgs.append(ofp_parser.OFPFlowMod(datapath, cookie,
                                                                              cookie_mask, table_id,
                                                                              ofp.OFPFC_DELETE,
                                                                              idle_timeout, hard_timeout,
                                                                              priority, buffer_id,
                                                                              ofp.OFPP_ANY,
                                                                              ofp.OFPG_ANY,
                                                                              0, match, inst))
                            self.send_msgs(datapath, msgs)
                    else:
                        switch = self._switches._get_switch(str_to_dpid(dp_id))
                        if switch is not None:
                            msgs = []
                            datapath = switch.dp
                            ofp = datapath.ofproto
                            ofp_parser = datapath.ofproto_parser
                            buffer_id = ofp.OFP_NO_BUFFER
                            for port in datapath.ports:
                                port_no = datapath.ports[port].port_no
                                port_name = datapath.ports[port].name
                                port_mac = datapath.ports[port].hw_addr
                                dp_vs_map = map_table.dp_port_to_vs_port(dp_id,
                                                                         port_no,
                                                                         port_name,
                                                                         port_mac)
                                if port_no == dp_port:
                                    continue

                                if dp_vs_map:
                                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                    if ip.version == 4:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_type=0x0800,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    ipv4_dst=(network, mask))
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_type=0x86DD,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    ipv6_dst=(network, mask))
                                    inst = []
                                    msgs.append(ofp_parser.OFPFlowMod(datapath, cookie,
                                                                      cookie_mask,
                                                                      table_id,
                                                                      ofp.OFPFC_DELETE,
                                                                      idle_timeout,
                                                                      hard_timeout,
                                                                      priority,
                                                                      buffer_id,
                                                                      ofp.OFPP_ANY,
                                                                      ofp.OFPG_ANY,
                                                                      0, match,
                                                                      inst))
                            self.send_msgs(datapath, msgs)
            else:
                for dpid, dp in self._datapaths.items():
                    if not is_rfvs(dpid):
                        msgs = []
                        ofp = dp.ofproto
                        ofp_parser = dp.ofproto_parser
                        buffer_id = ofp.OFP_NO_BUFFER
                        for port in dp.ports:
                            port_no = dp.ports[port].port_no
                            port_name = dp.ports[port].name
                            port_mac = dp.ports[port].hw_addr
                            dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                     port_no,
                                                                     port_name,
                                                                     port_mac)
                            if dp_vs_map:
                                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                if ip.version == 4:
                                    match = ofp_parser.OFPMatch(in_port=port_no,
                                                                eth_type=0x0800,
                                                                eth_dst=vs_port_hw_addr,
                                                                ipv4_dst=(network, mask))
                                else:
                                    match = ofp_parser.OFPMatch(in_port=port_no,
                                                                eth_type=0x86DD,
                                                                eth_dst=vs_port_hw_addr,
                                                                ipv6_dst=(network, mask))
                                inst = []
                                msgs.append(ofp_parser.OFPFlowMod(dp, cookie,
                                                                  cookie_mask,
                                                                  table_id,
                                                                  ofp.OFPFC_DELETE,
                                                                  idle_timeout,
                                                                  hard_timeout,
                                                                  priority,
                                                                  buffer_id,
                                                                  ofp.OFPP_ANY,
                                                                  ofp.OFPG_ANY,
                                                                  0, match,
                                                                  inst))
                        self.send_msgs(dp, msgs)

    def delete_host_flow(self, neigh, map_table, vsinterface, vs_ofport):
        ''' Delete flows for specific hosts. '''
        vsaddresses = vsinterface['IP-Addresses']
        vs_int_mac = vsinterface['mac-address']
        vs_name = vsinterface['ifname']
        priority = 38000
        neigh_ip = neigh['ipaddr']
        neigh_addr = IPAddress(neigh_ip)
        for address in vsaddresses:
            addr, anetmask = address
            addrip = IPAddress(addr)
            if addrip.version == neigh_addr.version:
                addrnet = IPNetwork(addr+'/'+str(anetmask))
                neighnet = IPNetwork(neigh_ip+'/'+str(anetmask))
                if addrnet == neighnet:
                    vs_dp_map = map_table.vs_port_to_dp_port(vs_name,
                                                             vs_ofport,
                                                             vs_int_mac)
                    if vs_dp_map:
                        dp_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                        switch = self._switches._get_switch(str_to_dpid(dp_id))
                        if switch is not None:
                            datapath = switch.dp
                            ofp = switch.dp.ofproto
                            ofp_parser = switch.dp.ofproto_parser
                            table_id = 0
                            buffer_id = ofp.OFP_NO_BUFFER
                            msgs = []
                            for port in datapath.ports:
                                port_no = datapath.ports[port].port_no
                                port_mac = datapath.ports[port].hw_addr
                                port_name = datapath.ports[port].name
                                dp_vs_map = map_table.dp_port_to_vs_port(dp_id,
                                                                         port_no,
                                                                         port_name,
                                                                         port_mac)
                                if dp_vs_map:
                                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                    if neigh_addr.version == 4:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_type=0x0800,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    ipv4_dst=neigh_ip)
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_type=0x86DD,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    ipv6_dst=neigh_ip)
                                    inst = []
                                    msgs.append(ofp_parser.OFPFlowMod(datapath,
                                                                      cookie,
                                                                      cookie_mask,
                                                                      table_id,
                                                                      ofp.OFPFC_DELETE_STRICT,
                                                                      priority,
                                                                      buffer_id,
                                                                      ofp.OFPP_ANY,
                                                                      ofp.OFPG_ANY,
                                                                      0, match,
                                                                      inst))
                            self.send_msgs(datapath, msgs)

    def new_dphost_add_flow(self, neigh, map_table, vsinterface, vs_ofport):
        ''' Update flow table with rules for hosts connected to
            the datapath ports that are detected later.
        '''
        vsaddresses = vsinterface['IP-Addresses']
        vs_int_mac = vsinterface['mac-address']
        vs_name = vsinterface['ifname']
        neigh_ip = neigh['ipaddr']
        neigh_mac = neigh['mac_addr']
        neigh_addr = IPAddress(neigh_ip)
        for address in vsaddresses:
            addr, anetmask = address
            addrip = IPAddress(addr)
            if addrip.version == neigh_addr.version:
                addrnet = IPNetwork(addr+'/'+str(anetmask))
                neighnet = IPNetwork(neigh_ip+'/'+str(anetmask))
                if addrnet == neighnet:
                    vs_dp_map = map_table.vs_port_to_dp_port(vs_name,
                                                             vs_ofport,
                                                             vs_int_mac)
                    if vs_dp_map:
                        dp_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                        ''' Get switches and install rules. '''
                        for dpid, dp in self._datapaths.items():
                            if not is_rfvs(dpid):
                                msgs = []
                                ofp = dp.ofproto
                                ofp_parser = dp.ofproto_parser
                                buffer_id = ofp.OFP_NO_BUFFER
                                priority = 38000
                                if dp_id == dpid_to_str(dpid):
                                    for port in dp.ports:
                                        port_no = dp.ports[port].port_no
                                        port_mac = dp.ports[port].hw_addr
                                        port_name = dp.ports[port].name
                                        dp_vs_map = map_table.dp_port_to_vs_port(dp_id,
                                                                                 port_no,
                                                                                 port_name,
                                                                                 port_mac)
                                        if port_no == dp_port:
                                            continue

                                        if dp_vs_map:
                                            vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                            if neigh_addr.version == 4:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=neigh_ip)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=neigh_ip)
                                            decrement_ttl = map_table.dp_dec_ttl[dp_id]
                                            actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                       ofp_parser.OFPActionSetField(eth_dst=neigh_mac),
                                                       ofp_parser.OFPActionOutput(port=dp_port)]
                                            actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                                            msgs.append(ofp_parser.OFPFlowMod(dp, cookie,
                                                                              cookie_mask,
                                                                              table_id,
                                                                              ofp.OFPFC_ADD,
                                                                              idle_timeout,
                                                                              hard_timeout,
                                                                              priority,
                                                                              buffer_id,
                                                                              ofp.OFPP_ANY,
                                                                              ofp.OFPG_ANY,
                                                                              ofp.OFPFF_SEND_FLOW_REM,
                                                                              match,
                                                                              inst))
                                    self.send_msgs(dp, msgs)
                                else:
                                    ''' Check for ISL. '''
                                    (isl_label, interswitch_links) = (
                                     map_table.dp_port_to_isl_labels(dp_id, dp_port))
                                    if (isl_label is not None):
                                        for port in dp.ports:
                                            port_no = dp.ports[port].port_no
                                            port_mac = dp.ports[port].hw_addr
                                            port_name = dp.ports[port].name
                                            dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                                     port_no,
                                                                                     port_name,
                                                                                     port_mac)
                                            if dp_vs_map:
                                                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                                if neigh_addr.version == 4:
                                                    match = ofp_parser.OFPMatch(in_port=port,
                                                                                eth_type=0x0800,
                                                                                eth_dst=vs_port_hw_addr,
                                                                                ipv4_dst=neigh_ip)
                                                else:
                                                    match = ofp_parser.OFPMatch(in_port=port,
                                                                                eth_type=0x86DD,
                                                                                eth_dst=vs_port_hw_addr,
                                                                                ipv6_dst=neigh_ip)
                                                decrement_ttl = map_table.dp_dec_ttl[dpid_to_str(dpid)]
                                                actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                           ofp_parser.OFPActionSetField(eth_dst=neigh_mac)]
                                                actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                                actions = self.labeller.push_action_meta(isl_label,
                                                                                         ofp_parser,
                                                                                         actions)
                                                for dp_isl_port, remote_dp in interswitch_links.items():
                                                    rem_dpid = remote_dp.keys()[0]
                                                    rem_isl_port = remote_dp[rem_dpid]

                                                    if rem_dpid == dpid_to_str(dpid):
                                                        actions += [ofp_parser.OFPActionOutput(port=rem_isl_port)]
                                                        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                                                        msgs.append(ofp_parser.OFPFlowMod(dp, cookie,
                                                                                          cookie_mask,
                                                                                          table_id,
                                                                                          ofp.OFPFC_ADD,
                                                                                          idle_timeout,
                                                                                          hard_timeout,
                                                                                          priority,
                                                                                          buffer_id,
                                                                                          ofp.OFPP_ANY,
                                                                                          ofp.OFPG_ANY,
                                                                                          ofp.OFPFF_SEND_FLOW_REM,
                                                                                          match, inst))
                                        self.send_msgs(dp, msgs)

    def convert_route_to_flow(self, route, map_table, iftable, neigh_table,
                              vsif_to_ofp, **next_hop):
        ''' Create flow rules from received route information. '''
        if 'host' in next_hop:
            for dpid, dp in self._datapaths.items():
                if not is_rfvs(dpid):
                    msgs = []
                    ofp = dp.ofproto
                    ofp_parser = dp.ofproto_parser
                    table_id = 0
                    idle_timeout = hard_timeout = 0
                    priority = 38000
                    buffer_id = ofp.OFP_NO_BUFFER
                    network = route[0]
                    netmask = str(route[2])
                    ip = IPNetwork(network+'/'+netmask)
                    mask = str(ip.netmask)
                    host = next_hop['host']
                    nh_mac = host['mac_addr']
                    vs_ifindex = host['ifindex']
                    vs_interface = self.find_with_ifindex(vs_ifindex, iftable)
                    decrement_ttl = map_table.dp_dec_ttl[dpid_to_str(dpid)]
                    if vs_interface:
                        vs_int_mac = vs_interface['mac-address']
                        vs_int_name = vs_interface['ifname']
                    if vs_ifindex in vsif_to_ofp:
                        vs_ofp_no = vsif_to_ofp[vs_ifindex]
                        vs_dp_map = map_table.vs_port_to_dp_port(vs_int_name,
                                                                 vs_ofp_no,
                                                                 vs_int_mac)
                        if vs_dp_map:
                            dp_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            '''
                                Verify that a host with the next-hop MAC address is
                                connected to a port on the datapath.
                            '''
                            if dp_id == dpid_to_str(dpid):
                                for port in dp.ports:
                                    port_name = dp.ports[port].name
                                    port_hw_addr = dp.ports[port].hw_addr
                                    port_no = dp.ports[port].port_no
                                    dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                             port_no,
                                                                             port_name,
                                                                             port_hw_addr)

                                    if dp_vs_map is None:
                                        pass
                                    else:
                                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                        if ip.version == 4:
                                            if network == '0.0.0.0':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=(network, mask))
                                            actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                       ofp_parser.OFPActionSetField(eth_dst=nh_mac),
                                                       ofp_parser.OFPActionOutput(port=dp_port)]
                                            actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                     actions)]
                                        else:
                                            if network == '::':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=(network, mask))
                                            actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                       ofp_parser.OFPActionSetField(eth_dst=nh_mac),
                                                       ofp_parser.OFPActionOutput(port=dp_port)]
                                            actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                     actions)]
                                        msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                          table_id, ofp.OFPFC_ADD,
                                                                          idle_timeout, hard_timeout,
                                                                          priority, buffer_id,
                                                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                          ofp.OFPFF_SEND_FLOW_REM,
                                                                          match, inst))
                            else:
                                '''
                                    The next-hop is connected to port on another
                                    DP. send packet out the ISL to that port
                                    or the fastpath link to dp0.
                                '''
                                for port in dp.ports:
                                    port_name = dp.ports[port].name
                                    port_hw_addr = dp.ports[port].hw_addr
                                    port_no = dp.ports[port].port_no
                                    dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                             port_no,
                                                                             port_name,
                                                                             port_hw_addr)
                                    if dp_vs_map is None:
                                        pass
                                    else:
                                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                        if ip.version == 4:
                                            if network == '0.0.0.0':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=(network, mask))
                                            actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                       ofp_parser.OFPActionSetField(eth_dst=nh_mac)]
                                        else:
                                            if network == '::':
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=network)
                                            else:
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=(network, mask))
                                            actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                       ofp_parser.OFPActionSetField(eth_dst=nh_mac)]
                                        actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                        (isl_label, interswitch_links) = (
                                         map_table.dp_port_to_isl_labels(dp_id, dp_port))

                                        (fp_label, rem_vs_port, dp_fs_port, vs_fs_port) = (
                                         map_table.dp_port_to_fp_labels(dpid_to_str(dpid), port_no))

                                        if (isl_label is not None):
                                            push_actions = self.labeller.push_action_meta(isl_label,
                                                                                          ofp_parser,
                                                                                          actions)
                                            for dp_isl_port, remote_dp in interswitch_links.items():
                                                rem_dpid = remote_dp.keys()[0]
                                                rem_isl_port = remote_dp[rem_dpid]
                                                if rem_dpid == dpid_to_str(dpid):
                                                    push_actions += [ofp_parser.OFPActionOutput(port=rem_isl_port)]
                                                    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                             push_actions)]
                                                    msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                                      table_id, ofp.OFPFC_ADD,
                                                                                      idle_timeout, hard_timeout,
                                                                                      priority, buffer_id,
                                                                                      ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                                      ofp.OFPFF_SEND_FLOW_REM,
                                                                                      match, inst))

                                        elif (fp_label is not None) and (dp_fs_port is not None):
                                            push_actions = self.labeller.push_action_meta(fp_label,
                                                                                          ofp_parser,
                                                                                          actions)
                                            push_actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
                                            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                     push_actions)]
                                            msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                              table_id, ofp.OFPFC_ADD,
                                                                              idle_timeout, hard_timeout,
                                                                              priority, buffer_id,
                                                                              ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                              ofp.OFPFF_SEND_FLOW_REM,
                                                                              match, inst))
                                            '''
                                                Install a rule on the virtual switch dp0 that pops the VLAN from packets
                                                sent over the fastpath link and output them to the virtual interface port
                                                which is the destination.
                                            '''
                                            vs_msg = []
                                            vswitch = self._switches. _get_switch(str_to_dpid(vs_id))
                                            vs_dp = vswitch.dp
                                            vs_ofp = vs_dp.ofproto
                                            vs_ofp_parser = vs_dp.ofproto_parser
                                            vs_match = vs_ofp_parser.OFPMatch(in_port=vs_fs_port,
                                                                              vlan_vid=(fp_label | ofproto.OFPVID_PRESENT),
                                                                              eth_src=vs_int_mac,
                                                                              eth_dst=nh_mac)
                                            (label, remote_vs_p, dpfs_port, vsfs_port) = (
                                             map_table.dp_port_to_fp_labels(dp_id, dp_port))
                                            vs_push_action = self.labeller.push_action_meta(label,
                                                                                            vs_ofp_parser)
                                            vs_inst = [vs_ofp_parser.OFPInstructionActions(vs_ofp.OFPIT_APPLY_ACTIONS,
                                                                                           vs_push_action)]
                                            vs_msg.append(vs_ofp_parser.OFPFlowMod(vs_dp, cookie, cookie_mask,
                                                                                   table_id, vs_ofp.OFPFC_ADD,
                                                                                   idle_timeout, hard_timeout,
                                                                                   priority, buffer_id,
                                                                                   vs_ofp.OFPP_ANY, vs_ofp.OFPG_ANY,
                                                                                   vs_ofp.OFPFF_SEND_FLOW_REM,
                                                                                   vs_match, vs_inst))
                                            self.send_msgs(vs_dp, vs_msg)
                                        else:
                                            actions += [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                                            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                     actions)]
                                            msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                              table_id, ofp.OFPFC_ADD,
                                                                              idle_timeout, hard_timeout,
                                                                              priority, buffer_id,
                                                                              ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                              ofp.OFPFF_SEND_FLOW_REM,
                                                                              match, inst))
                        self.send_msgs(dp, msgs)
                    else:
                        '''
                            The port on the Rhea VS does not have an OF port number,
                            this implies it is not mapped to any datapath port, packet would
                            be sent to he corresponding port on the Rhea VS and normal
                            routing would be applied.
                        '''
                        for port in dp.ports:
                            port_name = dp.ports[port].name
                            port_hw_addr = dp.ports[port].hw_addr
                            port_no = dp.ports[port].port_no
                            dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                     port_no,
                                                                     port_name,
                                                                     port_hw_addr)
                            if dp_vs_map is None:
                                pass
                            else:
                                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                if ip.version == 4:
                                    if network == '0.0.0.0':
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x800,
                                                                    ipv4_dst=network)
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x800,
                                                                    ipv4_dst=(network, mask))
                                else:
                                    if network == '::':
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x86DD,
                                                                    ipv6_dst=network)
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    eth_type=0x86DD,
                                                                    ipv6_dst=(network, mask))
                                (fp_label, rem_vs_port, dp_fs_port, vs_fs_port) = (
                                 map_table.dp_port_to_fp_labels(dpid_to_str(dpid), port_no))

                                if (fp_label is not None) and (dp_fs_port is not None):
                                    push_actions = self.labeller.push_action_meta(fp_label, ofp_parser)
                                    push_actions = self.decrement_ip_ttl(ofp_parser, push_actions, decrement_ttl)
                                    push_actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
                                    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                             push_actions)]
                                    msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                      table_id, ofp.OFPFC_ADD,
                                                                      idle_timeout, hard_timeout,
                                                                      priority, buffer_id,
                                                                      ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                      ofp.OFPFF_SEND_FLOW_REM,
                                                                      match, inst))
                                else:
                                    actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                                    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIIT_APPLY_ACTIONS,
                                                                             actions)]
                                    msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                      table_id, ofp.OFPFC_ADD,
                                                                      idle_timeout, hard_timeout,
                                                                      priority, buffer_id,
                                                                      ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                      ofp.OFPFF_SEND_FLOW_REM,
                                                                      match, inst))
                        self.send_msgs(dp, msgs)
        else:
            table_id = 0
            idle_timeout = hard_timeout = 0
            priority = 38000
            network = route[0]
            netmask = str(route[2])
            ip = IPNetwork(network+'/'+netmask)
            mask = str(ip.netmask)
            ''' get the mac address and vs_to_dp mappings of the next-hop '''
            vs_interface = next_hop['interface']
            vs_int_name = vs_interface['ifname']
            vs_int_mac = vs_interface['mac-address']
            vs_int_addresses = vs_interface['IP-Addresses']
            vs_int_index = vs_interface['ifindex']
            SameNetwork = False
            ''' compare network route with addresses on vs_interface. '''
            for address in vs_int_addresses:
                addr, anetmask = address
                if IPNetwork(addr+'/'+str(anetmask)) == ip:
                    SameNetwork = True
            ''' get OF Port number for interface '''
            if vs_int_index in vsif_to_ofp:
                vs_ofp_no = vsif_to_ofp[vs_int_index]
                vs_dp_map = map_table.vs_port_to_dp_port(vs_int_name,
                                                         vs_ofp_no,
                                                         vs_int_mac)
                if vs_dp_map:
                    dp_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                    dp_neighbours = []
                    decrement_ttl = map_table.dp_dec_ttl[dp_id]
                    for neigh in neigh_table:
                        if vs_int_index == neigh['ifindex']:
                            dp_neighbours.append(neigh)

                    if SameNetwork is True:
                        ''' Create rules and install for ports on that DP '''
                        switch = self._switches._get_switch(str_to_dpid(dp_id))
                        if switch is not None:
                            msgs = []
                            datapath = switch.dp
                            ofp = datapath.ofproto
                            ofp_parser = datapath.ofproto_parser
                            buffer_id = ofp.OFP_NO_BUFFER
                            for port in datapath.ports:
                                port_no = datapath.ports[port].port_no
                                port_mac = datapath.ports[port].hw_addr
                                port_name = datapath.ports[port].name
                                dp_vs_map = map_table.dp_port_to_vs_port(dp_id,
                                                                         port_no,
                                                                         port_name,
                                                                         port_mac)

                                if port_no == dp_port:
                                    continue

                                if dp_vs_map:
                                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                    if len(dp_neighbours) != 0:
                                        for neigh in dp_neighbours:
                                            host_ip = neigh['ipaddr']
                                            host_mac = neigh['mac_addr']
                                            hostip = IPAddress(host_ip)

                                            if (ip.version == 4) and (hostip.version == 4):
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x0800,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv4_dst=host_ip)
                                                actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                           ofp_parser.OFPActionSetField(eth_dst=host_mac),
                                                           ofp_parser.OFPActionOutput(port=dp_port)]
                                                actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                         actions)]
                                                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                                                  table_id, ofp.OFPFC_ADD,
                                                                                  idle_timeout, hard_timeout,
                                                                                  priority, buffer_id,
                                                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                                                  match, inst))
                                            if (ip.version == 6) and (hostip.version == 6):
                                                match = ofp_parser.OFPMatch(in_port=port_no,
                                                                            eth_type=0x86DD,
                                                                            eth_dst=vs_port_hw_addr,
                                                                            ipv6_dst=host_ip)
                                                actions = [ofp_parser.OFPActionSetField(eth_src=vs_int_mac),
                                                           ofp_parser.OFPActionSetField(eth_dst=host_mac),
                                                           ofp_parser.OFPActionOutput(port=dp_port)]
                                                actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                         actions)]
                                                msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                                                  table_id, ofp.OFPFC_ADD,
                                                                                  idle_timeout, hard_timeout,
                                                                                  priority, buffer_id,
                                                                                  ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                                  ofp.OFPFF_SEND_FLOW_REM,
                                                                                  match, inst))
                            self.send_msgs(datapath, msgs)

                    else:
                        switch = self._switches._get_switch(str_to_dpid(dp_id))
                        if switch is not None:
                            msgs = []
                            datapath = switch.dp
                            ofp = datapath.ofproto
                            ofp_parser = datapath.ofproto_parser
                            buffer_id = ofp.OFP_NO_BUFFER
                            for port in datapath.ports:
                                port_no = datapath.ports[port].port_no
                                port_name = datapath.ports[port].name
                                port_mac = datapath.ports[port].hw_addr
                                dp_vs_map = map_table.dp_port_to_vs_port(dp_id,
                                                                         port_no,
                                                                         port_name,
                                                                         port_mac)
                                if port_no == dp_port:
                                    continue

                                if dp_vs_map:
                                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                    if ip.version == 4:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_type=0x0800,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    ipv4_dst=(network, mask))
                                    else:
                                        match = ofp_parser.OFPMatch(in_port=port_no,
                                                                    eth_type=0x86DD,
                                                                    eth_dst=vs_port_hw_addr,
                                                                    ipv6_dst=(network, mask))
                                    (fp_label, rem_vs_port, dp_fs_port, vs_fs_port) = (
                                     map_table.dp_port_to_fp_labels(dp_id, port_no))

                                    if (fp_label is not None) and (dp_fs_port is not None):
                                        actions = self.labeller.push_action_meta(fp_label, ofp_parser)
                                        actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                        actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
                                        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                                 actions)]
                                        msgs.append(ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                                                          table_id, ofp.OFPFC_ADD,
                                                                          idle_timeout, hard_timeout,
                                                                          priority, buffer_id,
                                                                          ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                          ofp.OFPFF_SEND_FLOW_REM,
                                                                          match, inst))
                            self.send_msgs(datapath, msgs)

                else:
                    log.warn("No datapath port mapping found for Interface:%s,\
                             OF Port:%s on the virtual switch",
                             vs_int_name, vs_ofp_no)

            else:
                '''
                    Handle via FastPath
                '''
                for dpid, dp in self._datapaths.items():
                    if not is_rfvs(dpid):
                        msgs = []
                        ofp = dp.ofproto
                        ofp_parser = dp.ofproto_parser
                        buffer_id = ofp.OFP_NO_BUFFER
                        for port in dp.ports:
                            port_no = dp.ports[port].port_no
                            port_name = dp.ports[port].name
                            port_mac = dp.ports[port].hw_addr
                            dp_vs_map = map_table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                                     port_no,
                                                                     port_name,
                                                                     port_mac)
                            if dp_vs_map:
                                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                                decrement_ttl = map_table.dp_dec_ttl[dpid_to_str(dpid)]
                                if ip.version == 4:
                                    match = ofp_parser.OFPMatch(in_port=port_no,
                                                                eth_type=0x0800,
                                                                eth_dst=vs_port_hw_addr,
                                                                ipv4_dst=(network, mask))
                                else:
                                    match = ofp_parser.OFPMatch(in_port=port_no,
                                                                eth_type=0x86DD,
                                                                eth_dst=vs_port_hw_addr,
                                                                ipv6_dst=(network, mask))
                                (fp_label, rem_vs_port, dp_fs_port, vs_fs_port) = (
                                 map_table.dp_port_to_fp_labels(dpid_to_str(dpid), port_no))
                                if (fp_label is not None) and (dp_fs_port is not None):
                                    actions = self.labeller.push_action_meta(fp_label, ofp_parser)
                                    actions = self.decrement_ip_ttl(ofp_parser, actions, decrement_ttl)
                                    actions += [ofp_parser.OFPActionOutput(port=dp_fs_port)]
                                    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                                             actions)]
                                    msgs.append(ofp_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                                                      table_id, ofp.OFPFC_ADD,
                                                                      idle_timeout, hard_timeout,
                                                                      priority, buffer_id,
                                                                      ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                                      ofp.OFPFF_SEND_FLOW_REM,
                                                                      match, inst))
                        self.send_msgs(dp, msgs)

    def add_host(self, ip_addr, mac, dp_port, dp_id):
        '''
            Add neighbours discovered to RheaFlowProcessor's
            internal HostonDP table.
        '''
        if (ip_addr, mac) in self.HostonDP:
            old_port, old_dpid = self.HostonDP[(ip_addr, mac)]
            if (old_port != dp_port) and (old_dpid != dp_id):
                del self.HostonDP[(ip_addr, mac)]
                self.HostonDP[(ip_addr, mac)] = (dp_port, dp_id)
        else:
            self.HostonDP[(ip_addr, mac)] = (dp_port, dp_id)

    def DPHostWithIP(self, ip_addr):
        '''
            Find a hosts in the neighbour table using IP address.
        '''
        addrnet = IPNetwork(ip_addr)
        for (ip_, mac) in self.HostonDP.keys():
            hostnet = IPNetwork(ip_)
            if addrnet.ip == hostnet.ip:
                return (ip_, mac)
        return None

    def DPHostWithMac(self, mac):
        '''
            Find host  in the neighbour table using MAC address.
        '''
        for (ip_addr, _mac_) in self.HostonDP.keys():
            if mac == _mac_:
                return (ip_addr, _mac_)
        return None

    def HostonDPPort(self, dp_port, dp_id):
        '''
            Return a list of hosts connected to the
            given port on a datapath.
        '''
        hosts = []
        for (ip_addr, mac), (port, dpid) in self.HostonDP.items():
            if (port == dp_port) and (dpid == dp_id):
                hosts.append((ip_addr, mac))
        return hosts

    def rhost_in_hostTable(self, HostTable, mac_addr):
        '''
            Find a host in the HostTable with MAC address.
        '''
        for host in HostTable:
            if mac_addr in host.itervalues():
                return host
        return None

    def find_by_index(self, interfaces, ifindex):
        for interface in interfaces:
            if ifindex == interface['ifindex']:
                return interface
        return None

    def handle_packet_in(self, msg, maptable, interfacetable, vsif_to_ofp,
                         HostTable):
        '''
            Output packet-in messages received from datapaths
            connected to the controller.
        '''
        _msg = msg
        dp = _msg.datapath
        dp_id = dp.id
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        _table = maptable
        _vsif_ofp_map = vsif_to_ofp
        _ifTable = interfacetable

        if is_rfvs(dp_id):
            in_port = _msg.match['in_port']

            if in_port == ofp.OFPP_LOCAL:
                log.warn("%s received from dp0's OpenFlow LOCAL port", _msg.data)
                log.warn("The received packet will be discarded")
                return
            for iface_index, vs_ofp_no in _vsif_ofp_map.items():
                if vs_ofp_no == in_port:
                    iface = self.find_by_index(_ifTable, iface_index)
                    if iface:
                        vs_name = iface['ifname']
                        vs_mac = iface['mac-address']
                        vs_dp_map = _table.vs_port_to_dp_port(vs_name,
                                                              vs_ofp_no,
                                                              vs_mac)
                        if vs_dp_map:
                            datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            switch = self._switches._get_switch(str_to_dpid(datapath_id))
                            datapath = switch.dp
                            if switch is not None:
                                self.send_pkt_out(datapath, dp_port, _msg.data)
                                return
                            else:
                                log.warn("datapath %s not found!!! Dropping packet", datapath_id)
                                return
        else:
            in_port = _msg.match['in_port']
            if not in_port:
                log.warn("This has no in-port. Drop!!!")
                return
            else:
                port = self._switches._get_port(dp_id, in_port)
                dp_port_hw_addr = port.hw_addr
                dp_port_name = port.name
                dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                      in_port,
                                                      dp_port_name,
                                                      dp_port_hw_addr)
                if dp_vs_map is None:
                    log.warn("Packet-in received from unmapped port:%s on dp_id:%s",
                             in_port, dpid_to_str(dp_id))
                    log.warn("Check rheaflow configuration")
                    return
                else:
                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                    vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                    vs_dp = vswitch.dp
                    self.send_pkt_out(vs_dp, vs_port, _msg.data)
                    return

    def debug_handle_packet_in(self, msg, maptable, interfacetable, vsif_to_ofp,
                               HostTable):
        '''
            Process and parse packet-in messages received from
            datapaths connected to the controller.
        '''
        _msg = msg
        dp = _msg.datapath
        dp_id = dp.id
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        _table = maptable
        _ifTable = interfacetable
        _vsif_ofp_map = vsif_to_ofp
        _remote_hosts = HostTable

        if is_rfvs(dp_id):
            pkt = packet.Packet(data=_msg.data)
            pkt_ethernet = pkt.get_protocol(ethernet)
            pkt_arp = pkt.get_protocol(arp)
            pkt_icmp = pkt.get_protocol(icmp)
            pkt_icmpv6 = pkt.get_protocol(icmpv6)
            pkt_ipv4 = pkt.get_protocol(ipv4)
            pkt_ipv6 = pkt.get_protocol(ipv6)
            in_port = _msg.match['in_port']

            if in_port == ofp.OFPP_LOCAL:
                log.warn("%s received from dp0's OpenFlow LOCAL port", pkt)
                log.warn("The received packet will be discarded")
                return

            if not pkt_ethernet:
                log.warn("%s is not an ethernet packet, dropping!!!", pkt)
                return

            if pkt_arp:
                if pkt_arp.opcode == ARP_REQUEST:
                    src_mac = pkt_arp.src_mac
                    dst_ip = pkt_arp.dst_ip
                    vs_iface = self.find_with_mac(src_mac, _ifTable)
                    if vs_iface is not None:
                        vs_index = vs_iface['ifindex']
                        vs_name = vs_iface['ifname']
                        vs_ofp_no = _vsif_ofp_map[vs_index]
                        # get vs_dp_map
                        vs_dp_map = _table.vs_port_to_dp_port(vs_name,
                                                              vs_ofp_no,
                                                              src_mac)
                        if vs_dp_map:
                            datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            switch = self._switches._get_switch(str_to_dpid(datapath_id))
                            datapath = switch.dp
                            if switch is not None:
                                self.send_pkt_out(datapath, dp_port, _msg.data)
                                return
                            else:
                                log.warn("datapath %s not found!!!\
                                         Dropping packet", datapath_id)
                                return
                        else:
                            log.warn("No DP mapping found for %s,%s,%s.\
                                     Dropping packet", vs_name, vs_ofp_no,
                                     src_mac)
                            return
                    else:
                        rhost = self.DPHostWithMac(src_mac)
                        if rhost is not None:
                            port_out, rdp_id = self.HostonDP[rhost]
                            port = self._switches._get_port(str_to_dpid(rdp_id),
                                                            port_out)
                            port_name = port.name
                            port_addr = port.hw_addr
                            dp_vs_map = _table.dp_port_to_vs_port(rdp_id,
                                                                  port_out,
                                                                  port_name,
                                                                  port_addr)
                            vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                            self.send_pkt_out(dp, vs_port, _msg.data)
                            return
                        else:
                            vs_iface = self.find_with_ip(dst_ip, _ifTable)
                            if vs_iface is not None:
                                vs_index = vs_iface['ifindex']
                                vs_ofp_no = _vsif_ofp_map[vs_index]
                                self.send_pkt_out(dp, vs_ofp_no, _msg.data)
                                return

                elif pkt_arp.opcode == ARP_REPLY:
                    src_mac = pkt_arp.src_mac
                    src_ip = pkt_arp.src_ip
                    dst_mac = pkt_arp.dst_mac
                    dst_ip = pkt_arp.dst_ip
                    vs_iface = self.find_with_mac(src_mac, _ifTable)
                    if vs_iface is not None:
                        vs_index = vs_iface['ifindex']
                        vs_name = vs_iface['ifname']
                        vs_ofp_no = _vsif_ofp_map[vs_index]
                        vs_dp_map = _table.vs_port_to_dp_port(vs_name,
                                                              vs_ofp_no,
                                                              src_mac)
                        if vs_dp_map:
                            datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            switch = self._switches._get_switch(str_to_dpid(datapath_id))
                            datapath = switch.dp
                            if switch is not None:
                                self.add_host(dst_ip, dst_mac, dp_port,
                                              datapath_id)
                                self.send_pkt_out(datapath, dp_port, _msg.data)
                            return
                        else:
                            log.warn("datapath %s not found!!! Dropping packet",
                                     datapath_id)
                            return
                        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                   len(_msg.data))]
                        buffer_id = ofp.OFP_NO_BUFFER
                        in_port = ofp.OFPP_CONTROLLER
                        packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                             in_port, actions,
                                                             _msg.data)
                        dp.send_msg(packet_out)
                        return
                    else:
                        vs_iface = self.find_with_mac(dst_mac, _ifTable)
                        vs_index = vs_iface['ifindex']
                        vs_ofp_no = _vsif_ofp_map[vs_index]
                        if vs_ofp_no is not None:
                            self.send_pkt_out(dp, vs_ofp_no, _msg.data)
                            log.warn("%s ARP reply is meant for %s", _msg.data,
                                     dst_mac)
                        else:
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                                  len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            in_port = ofp.OFPP_CONTROLLER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                        return
                else:
                    log.warn("Unrecognized ARP packet, dropping %s", pkt)
                    return

            if pkt_icmp:
                if pkt_icmp.type == ICMP_ECHO_REQUEST:
                    src_mac = pkt_ethernet.src
                    dst_mac = pkt_ethernet.dst
                    vs_iface = self.find_with_mac(src_mac, _ifTable)
                    if vs_iface is not None:
                        vs_index = vs_iface['ifindex']
                        vs_name = vs_iface['ifname']
                        vs_ofp_no = _vsif_ofp_map[vs_index]
                        vs_dp_map = _table.vs_port_to_dp_port(vs_name,
                                                              vs_ofp_no,
                                                              src_mac)
                        if vs_dp_map:
                            datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            rhost = self.DPHostWithMac(dst_mac)
                            if rhost is not None:
                                (ip_addr, mac_) = rhost
                                port_out, rdp_id = self.HostonDP[rhost]
                                if (datapath_id == rdp_id):
                                    switch = self._switches._get_switch(str_to_dpid(rdp_id))
                                    datapath = switch.dp
                                    self.send_pkt_out(datapath, port_out, _msg.data)
                                    return
                            else:
                                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                                buffer_id = ofp.OFP_NO_BUFFER
                                packet_out = ofp_parser.OFPPacketOut(dp,
                                                                     buffer_id,
                                                                     in_port,
                                                                     actions,
                                                                     _msg.data)
                                dp.send_msg(packet_out)
                                return
                        else:
                            rhost = self.DPHostWithMac(dst_mac)
                            if rhost is not None:
                                (ip_addr, mac_) = rhost
                                port_out, rdp_id = self.HostonDP[rhost]
                                switch = self._switches._get_switch(str_to_dpid(rdp_id))
                                datapath = switch.dp
                                self.send_pkt_out(datapath, port_out, _msg.data)
                                return
                            else:
                                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                                buffer_id = ofp.OFP_NO_BUFFER
                                packet_out = ofp_parser.OFPPacketOut(dp,
                                                                     buffer_id,
                                                                     in_port,
                                                                     actions,
                                                                     _msg.data)
                                dp.send_msg(packet_out)
                                return
                    else:
                        vs_iface = self.find_with_mac(dst_mac, _ifTable)
                        if vs_iface is not None:
                            vs_index = vs_iface['ifindex']
                            vs_name = vs_iface['ifname']
                            vs_ofp_no = _vsif_ofp_map[vs_index]
                            vs_dp_map = _table.vs_port_to_dp_port(vs_name,
                                                                  vs_ofp_no,
                                                                  dst_mac)
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                                  len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                            return

                else:
                    src_mac = pkt_ethernet.src
                    dst_mac = pkt_ethernet.dst
                    vs_iface = self.find_with_mac(src_mac, _ifTable)
                    if vs_iface is not None:
                        vs_index = vs_iface['ifindex']
                        vs_name = vs_iface['ifname']
                        vs_ofp_no = _vsif_ofp_map[vs_index]
                        vs_dp_map = _table.vs_port_to_dp_port(vs_name,
                                                              vs_ofp_no,
                                                              src_mac)
                        if vs_dp_map:
                            datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                            rhost = self.DPHostWithMac(dst_mac)
                            if rhost is not None:
                                (ip_addr, mac) = rhost
                                port_out, rdpid = self.HostonDP[rhost]
                                if (datapath_id == rdpid):
                                    switch = self._switches._get_switch(str_to_dpid(rdpid))
                                    datapath = switch.dp
                                    self.send_pkt_out(datapath, port_out,
                                                      _msg.data)
                                    return
                            else:
                                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                                buffer_id = ofp.OFP_NO_BUFFER
                                packet_out = ofp_parser.OFPPacketOut(dp,
                                                                     buffer_id,
                                                                     in_port,
                                                                     actions,
                                                                     _msg.data)
                                dp.send_msg(packet_out)
                                return
                        else:
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                            return
                    else:
                        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                              len(_msg.data))]
                        buffer_id = ofp.OFP_NO_BUFFER
                        packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                             in_port, actions,
                                                             _msg.data)
                        dp.send_msg(packet_out)
                        return

            if pkt_icmpv6:
                vsindex = None
                vsport = None
                for index, vs_port in _vsif_ofp_map.items():
                    if vs_port == in_port:
                        vsindex = index
                        vsport = vs_port
                        break

                if vsindex:
                    vs_iface = self.find_with_ifindex(vsindex, _ifTable)
                    if vs_iface is None:
                        return
                    vs_name = vs_iface['ifname']
                    vs_port_hw_addr = vs_iface['mac-address']
                    vs_dp_map = _table.vs_port_to_dp_port(vs_name, vsport,
                                                          vs_port_hw_addr)
                    if vs_dp_map:
                        datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                        switch = self._switches._get_switch(str_to_dpid(datapath_id))
                        datapath = switch.dp
                        self.send_pkt_out(datapath, dp_port, _msg.data)
                        return

            if pkt_ipv4:
                src_mac = pkt_ethernet.src
                dst_mac = pkt_ethernet.dst
                src_ip = pkt_ipv4.src
                dst_ip = pkt_ipv4.dst

                vs_iface = self.find_with_mac(src_mac, _ifTable)
                if vs_iface is not None:
                    vs_index = vs_iface['ifindex']
                    vs_name = vs_iface['ifname']
                    vs_ofp_no = _vsif_ofp_map[vs_index]
                    vs_dp_map = _table.vs_port_to_dp_port(vs_name, vs_ofp_no,
                                                          src_mac)
                    if vs_dp_map:
                        datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                        switch = self._switches._get_switch(str_to_dpid(datapath_id))
                        datapath = switch.dp
                        rhost = self.DPHostWithMac(dst_mac)
                        dp_neighbour = self.rhost_in_hostTable(_remote_hosts,
                                                               dst_mac)
                        if dp_neighbour is not None:
                            self.send_pkt_out(datapath, dp_port, _msg.data)
                            return
                        else:
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                            return
                    else:
                        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                              len(_msg.data))]
                        buffer_id = ofp.OFP_NO_BUFFER
                        packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                             in_port, actions,
                                                             _msg.data)
                        dp.send_msg(packet_out)
                        return
                else:
                    actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                          len(_msg.data))]
                    buffer_id = ofp.OFP_NO_BUFFER
                    packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                         in_port, actions,
                                                         _msg.data)
                    dp.send_msg(packet_out)
                    return

            if pkt_ipv6:
                src_mac = pkt_ethernet.src
                dst_mac = pkt_ethernet.dst
                vs_iface = self.find_with_mac(src_mac, _ifTable)
                if vs_iface is not None:
                    vs_index = vs_iface['ifindex']
                    vs_name = vs_iface['ifname']
                    vs_ofp_no = _vsif_ofp_map[vs_index]
                    vs_dp_map = _table.vs_port_to_dp_port(vs_name, vs_ofp_no,
                                                          src_mac)
                    if vs_dp_map:
                        datapath_id, dp_port, dp_port_name, dp_port_hw_addr = vs_dp_map
                        switch = self._switches._get_switch(str_to_dpid(datapath_id))
                        datapath = switch.dp
                        rhost = self.DPHostWithMac(dst_mac)
                        dp_neighbour = self.rhost_in_hostTable(_remote_hosts,
                                                               dst_mac)
                        if dp_neighbour is not None:
                            self.send_pkt_out(datapath, dp_port, _msg.data)
                            return
                        else:
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                            return
                    else:
                        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                              len(_msg.data))]
                        buffer_id = ofp.OFP_NO_BUFFER
                        packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                             in_port, actions,
                                                             _msg.data)
                        dp.send_msg(packet_out)
                        return
                else:
                    actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                          len(_msg.data))]
                    buffer_id = ofp.OFP_NO_BUFFER
                    packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                         in_port, actions,
                                                         _msg.data)
                    dp.send_msg(packet_out)
                    return
        else:
            pkt = packet.Packet(data=_msg.data)
            pkt_ethernet = pkt.get_protocol(ethernet)
            pkt_arp = pkt.get_protocol(arp)
            pkt_icmp = pkt.get_protocol(icmp)
            pkt_icmpv6 = pkt.get_protocol(icmpv6)
            pkt_ipv4 = pkt.get_protocol(ipv4)
            pkt_ipv6 = pkt.get_protocol(ipv6)
            in_port = _msg.match['in_port']

            if not in_port:
                log.warn("This has no in-port. Dropping packet!!!")
                return
            else:
                port = self._switches._get_port(dp_id, in_port)
                dp_port_hw_addr = port.hw_addr
                dp_port_name = port.name
                dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                      in_port,
                                                      dp_port_name,
                                                      dp_port_hw_addr)
                if dp_vs_map is None:
                    log.warn("Packet-in received from unmapped port:%s on dp_id:%s",
                             in_port, dpid_to_str(dp_id))
                    log.warn("Check rheaflow configuration!!!")
                    return

            if not pkt_ethernet:
                log.warn("%s is not an ethernet packet, dropping!!!", pkt)
                return

            if pkt_arp:
                if pkt_arp.opcode == ARP_REQUEST:
                    src_mac = pkt_arp.src_mac
                    src_ip = pkt_arp.src_ip
                    dst_ip = pkt_arp.dst_ip
                    port = self._switches._get_port(dp_id, in_port)
                    dp_port_hw_addr = port.hw_addr
                    dp_port_name = port.name
                    dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                          in_port,
                                                          dp_port_name,
                                                          dp_port_hw_addr)
                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                    if src_mac == vs_port_hw_addr:
                        self.send_pkt_out(dp, in_port, _msg.data)
                        return
                    else:
                        self.add_host(src_ip, src_mac, in_port,
                                      dpid_to_str(dp_id))
                        vs_iface = self.find_with_ip(dst_ip, _ifTable)
                        if vs_iface is not None:
                            vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                            vs_dp = vswitch.dp
                            self.send_pkt_out(vs_dp, vs_port, _msg.data)
                            return
                        else:
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,
                                                                  len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            in_port = ofp.OFPP_CONTROLLER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                            return
                else:
                    src_mac = pkt_arp.src_mac
                    src_ip = pkt_arp.src_ip
                    dst_mac = pkt_arp.dst_mac
                    dst_ip = pkt_arp.dst_ip
                    port = self._switches._get_port(dp_id, in_port)
                    dp_port_hw_addr = port.hw_addr
                    dp_port_name = port.name
                    dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                          in_port,
                                                          dp_port_name,
                                                          dp_port_hw_addr)
                    if (dp_vs_map is None):
                        return
                    else:
                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                        if vs_port_hw_addr == dst_mac:
                            self.add_host(src_ip, src_mac, in_port,
                                          dpid_to_str(dp_id))
                            vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                            vs_dp = vswitch.dp
                            self.send_pkt_out(vs_dp, vs_port, _msg.data)
                            return
                        elif vs_port_hw_addr == src_mac:
                            self.add_host(dst_ip, dst_mac, in_port,
                                          dpid_to_str(dp_id))
                            self.send_pkt_out(dp, in_port, _msg.data)
                            return
                        else:
                            self.add_host(src_ip, src_mac, in_port,
                                          dpid_to_str(dp_id))
                            self.add_host(dst_ip, dst_mac, in_port,
                                          dpid_to_str(dp_id))
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, len(_msg.data))]
                            buffer_id = ofp.OFP_NO_BUFFER
                            packet_out = ofp_parser.OFPPacketOut(dp, buffer_id,
                                                                 in_port,
                                                                 actions,
                                                                 _msg.data)
                            dp.send_msg(packet_out)
                            return

            if pkt_icmp:
                if pkt_icmp.type == ICMP_ECHO_REQUEST:
                    src_mac = pkt_ethernet.src
                    dst_mac = pkt_ethernet.dst
                    port = self._switches._get_port(dp_id, in_port)
                    dp_port_hw_addr = port.hw_addr
                    dp_port_name = port.name
                    dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                          in_port,
                                                          dp_port_name,
                                                          dp_port_hw_addr)
                    if (dp_vs_map is None):
                        log.warn("Found no DP mapping for port %s for ICMP\
                                 request, dropping", in_port)
                        return
                    else:
                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                        if dst_mac == vs_port_hw_addr:
                            vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                            vs_dp = vswitch.dp
                            self.send_pkt_out(vs_dp, vs_port, _msg.data)
                            return
                        elif src_mac == vs_port_hw_addr:
                            self.send_pkt_out(dp, in_port, _msg.data)
                            return
                        else:
                            self.send_pkt_out(dp, in_port, _msg.data)
                            log.warn("We don't know where it came from,\
                                      ICMP request packet is been sent back\
                                      to dp")
                            return

                else:
                    src_mac = pkt_ethernet.src
                    dst_mac = pkt_ethernet.dst
                    port = self._switches._get_port(dp_id, in_port)
                    dp_port_hw_addr = port.hw_addr
                    dp_port_name = port.name
                    dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                          in_port,
                                                          dp_port_name,
                                                          dp_port_hw_addr)
                    if (dp_vs_map is None):
                        log.warn("No DP mapping found for port %s for ICMP\
                                 reply, dropping", in_port)
                        return
                    else:
                        vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                        if vs_port_hw_addr == dst_mac:
                            vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                            vs_dp = vswitch.dp
                            self.send_pkt_out(vs_dp, vs_port, _msg.data)
                            return
                        elif vs_port_hw_addr == src_mac:
                            self.send_pkt_out(dp, in_port, _msg.data)
                            return
                        else:
                            self.send_pkt_out(dp, in_port, _msg.data)
                            log.warn("We don't where it came from so we sent\
                                     ICMP reply back to DP")
                            return

            if pkt_icmpv6:
                port = self._switches._get_port(dp_id, in_port)
                dp_port_hw_addr = port.hw_addr
                dp_port_name = port.name
                dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                      in_port,
                                                      dp_port_name,
                                                      dp_port_hw_addr)
                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                vs_dp = vswitch.dp
                self.send_pkt_out(vs_dp, vs_port, _msg.data)
                return

            if pkt_ipv4:
                src_mac = pkt_ethernet.src
                src_ip = pkt_ipv4.src
                dst_mac = pkt_ethernet.dst
                dst_ip = pkt_ipv4.dst
                port = self._switches._get_port(dp_id, in_port)
                dp_port_hw_addr = port.hw_addr
                dp_port_name = port.name
                dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                      in_port,
                                                      dp_port_name,
                                                      dp_port_hw_addr)
                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                if (dst_mac == vs_port_hw_addr):
                    vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                    vs_dp = vswitch.dp
                    self.send_pkt_out(vs_dp, vs_port, _msg.data)
                    return

            if pkt_ipv6:
                src_mac = pkt_ethernet.src
                src_ip = pkt_ipv6.src
                dst_mac = pkt_ethernet.dst
                dst_ip = pkt_ipv6.dst
                port = self._switches._get_port(dp_id, in_port)
                dp_port_hw_addr = port.hw_addr
                dp_port_name = port.name
                dp_vs_map = _table.dp_port_to_vs_port(dpid_to_str(dp_id),
                                                      in_port,
                                                      dp_port_name,
                                                      dp_port_hw_addr)
                vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                vswitch = self._switches._get_switch(str_to_dpid(vs_id))
                vs_dp = vswitch.dp
                self.send_pkt_out(vs_dp, vs_port, _msg.data)
                return

    def send_msgs(self, dp, msgs):
        for msg in msgs:
            dp.send_msg(msg)

    def send_pkt_out(self, dp, port, msg_data):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(port, len(msg_data))]
        buffer_id = ofp.OFP_NO_BUFFER
        in_port = ofp.OFPP_CONTROLLER
        packet_out = ofp_parser.OFPPacketOut(dp, buffer_id, in_port, actions,
                                             msg_data)
        dp.send_msg(packet_out)

#!/usr/bin/env python
#-*- coding:utf-8 -*-
#
# Copyright (C) 2016 Oladimeji Fayomi, University of Waikato.
#
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
# Name: RheaController.py
# Author : Dimeji Fayomi
# Created : 28 November 2015
# Last Modified :
# Version : 1.0
# Description: This scripts handles OF switch registration and adds
#              ports as necessary to the virtual switch dp0

import sys
import subprocess
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.topology import switches, event
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib import hub
from ryu import cfg
from RheaYAML import RheaYAML
from RheaNLSocket import RheaNLSocket
from pyroute2 import IPRoute
import RheaFlowEvents
from RheaRouteReceiver import RheaRouteReceiver
from RheaFlowProcessor import RheaFlowProcessor
from RheaFastpath import MetaVLAN
from log import log
import traceback
import time

vs_id = '7266767372667673'
RFVS_PREFIX = 0x72667673
is_rfvs = lambda dp_id: not ((dp_id >> 32) ^ RFVS_PREFIX)

vsdevices = []

CONF = cfg.CONF
CONF.register_opts([
            cfg.StrOpt('rhea-config', default='/usr/local/etc/ryu/config.yaml')
            ])

config_file = CONF.rhea_config


class Table:
    ''' Association table class is used to map
        datapath ports to their corresponding
        ports on the virtual switch.
    '''
    def __init__(self):
        self.dp_to_vs = {}
        self.vs_to_dp = {}
        self.fastpaths = {}
        self.isl = {}
        self.dp_dec_ttl = {}
        self.fastpath_switch = {}

    def update_dp_port(self, dp_id, dp_port, dp_port_name, dp_port_hw_addr,
                       vs_port_name, vs_port, vs_port_hw_addr):
        if (dp_id, dp_port, dp_port_name, dp_port_hw_addr) in self.dp_to_vs:
            old_vs_port = (self.dp_to_vs[(dp_id,
                           dp_port, dp_port_name, dp_port_hw_addr)])
            del self.vs_to_dp[old_vs_port]

        self.dp_to_vs[(dp_id, dp_port, dp_port_name, dp_port_hw_addr)] = (vs_port_name,
                                                                          vs_port,
                                                                          vs_port_hw_addr)

        self.vs_to_dp[(vs_port_name, vs_port, vs_port_hw_addr)] = (dp_id,
                                                                   dp_port,
                                                                   dp_port_name,
                                                                   dp_port_hw_addr)

        log.info("dp_to_vs table: %s", self.dp_to_vs)
        log.info("vs_to_dp table: %s", self.vs_to_dp)

    def update_dp_dec_ttl(self, dp_id, decrement_ttl=False):
        if dp_id in self.dp_dec_ttl:
            del self.dp_dec_ttl[dp_id]
        self.dp_dec_ttl[dp_id] = decrement_ttl

    def set_fastpath_switch(self, dp_id, dp_fastpath_port, vs_fastpath_port):
        if dp_id in self.fastpath_switch:
            del self.fastpath_switch[dp_id]

        self.fastpath_switch[dp_id] = (dp_fastpath_port, vs_fastpath_port)

    def update_fastpath(self, dp_id, dp_port, fastpath_label, vs_port,
                        dp_fastpath_port, vs_fastpath_port):
        if (dp_id, dp_port) in self.fastpaths:
            del self.fastpaths[(dp_id, dp_port)]

        self.fastpaths[(dp_id, dp_port)] = (fastpath_label, vs_port,
                                            dp_fastpath_port,
                                            vs_fastpath_port)
        log.info("fastpath table: %s", self.fastpaths)

    def find_isl(self, dp_id):
        all_isl = []
        for (id_, port) in self.isl.keys():
            if id_ == dp_id:
                label, islinks = self.isl[(id_, port)]
                for isl_port, remote in islinks.items():
                    log.info("remote in find_isl: %s", remote)
                    if remote not in all_isl:
                        all_isl.append(remote)

        return all_isl

    def opposite_link(self, dp_id, port):
        for (id_, port) in self.isl.keys():
            if id_ == dp_id:
                label, islinks = self.isl[(id_, port)]
                for isl_port, remote in islinks.items():
                    log.info("remote in opposite_link: %s", remote)
                    if isl_port == port:
                        return remote
        return None

    def find_path(self, dp_id1, dp_id2):
        dp_id1h = str_to_dpid(dp_id1)
        dp_id2h = str_to_dpid(dp_id2)
        if self.fastpath_switch:
            fastpath_dpid = self.fastpath_switch.keys()[0]
            dp_fastpath_port, vs_fastpath_port = self.fastpath_switch[fastpath_dpid]
        else:
            fastpath_dpid = None

        if dp_id1 == fastpath_dpid:
            if is_rfvs(dp_id2h):
                path = [(dp_id1, dp_fastpath_port, dp_id2, vs_fastpath_port)]
                return path
            else:
                for (id_, port) in self.isl.keys():
                    if id_ == dp_id1:
                        label, islinks = self.isl[(id_, port)]
                        for isl_port in islinks:
                            remote_switch = islinks[isl_port]
                            remote_dpid = remote_switch.keys()[0]
                            remote_dpid_port = remote_switch[remote_dpid]
                            if dp_id2 in remote_switch:
                                dpid2_port = remote_switch[dp_id2]
                                path = [(dp_id1, isl_port, dp_id2, dpid2_port)]
                                return path
                            else:
                                recursive_path = self.find_path(remote_dpid, dp_id2)
                                path = [(dp_id1, isl_port, remote_dpid, remote_dpid_port)]
                                if recursive_path is None:
                                    return None

                                path.extend(recursive_path)
                                return path

        if dp_id2 == fastpath_dpid:
            if is_rfvs(dp_id1h):
                path = [(dp_id1, vs_fastpath_port, dp_id2, vs_fastpath_port)]
                return path
            else:
                for (id_, port) in self.isl.keys():
                    if id_ == dp_id2:
                        label, islinks = self.isl[(id_, port)]
                        for isl_port in islinks:
                            remote_switch = islinks[isl_port]
                            remote_dpid = remote_switch.keys()[0]
                            remote_dpid_port = remote_switch[remote_dpid]
                            if dp_id1 in remote_switch:
                                dpid1_port = remote_switch[dp_id1]
                                path = [(dp_id1, dpid1_port, dp_id2, isl_port)]
                                return path
                            else:
                                recursive_path = self.find_path(dp_id1, remote_dpid)
                                if recursive_path is None:
                                    return None

                                path = [(remote_dpid, remote_dpid_port, dp_id2, isl_port)]
                                recursive_path.extend(path)
                                return recursive_path

        if (dp_id1 is not fastpath_dpid) and (dp_id2 is not fastpath_dpid):
            for (id_, port) in self.isl.keys():
                if id_ == dp_id1:
                    label, islinks = self.isl[(id_, port)]
                    for isl_port in islinks:
                        remote_switch = islinks[isl_port]
                        remote_dpid = remote_switch.keys()[0]
                        remote_dpid_port = remote_switch[remote_dpid]
                        if dp_id2 in remote_switch:
                            dpid2_port = remote_switch[dp_id2]
                            path = [(dp_id1, isl_port, dp_id2, dpid2_port)]
                            return path
                        else:
                            other_isls = self.find_isl(remote_dpid)
                            for other_isl in other_isls:
                                if dp_id2 in other_isl:
                                    dpid2_port = other_isl[dp_id2]
                                    opposite = self.opposite_link(dp_id2, dpid2_port)
                                    if opposite is not None:
                                        opposite_rem = opposite.keys()[0]
                                        if opposite_rem == remote_dpid:
                                            opposite_dpid_port = opposite[opposite_rem]
                                            path = [(dp_id1, isl_port, remote_dpid, remote_dpid_port),
                                                    (remote_dpid, opposite_dpid_port, dp_id2, dpid2_port)]
                                            return path
                if id_ == dp_id2:
                    label, islinks = self.isl[(id_, port)]
                    for isl_port in islinks:
                        remote_switch = islinks[isl_port]
                        remote_dpid = remote_switch.keys()[0]
                        remote_dpid_port = remote_switch[remote_dpid]
                        if dp_id1 in remote_switch:
                            dpid1_port = remote_switch[dp_id1]
                            path = [(dp_id1, dpid1_port, dp_id2, isl_port)]
                            return path
                        else:
                            other_isls = self.find_isl(remote_dpid)
                            for other_isl in other_isls:
                                if dp_id1 in other_isl:
                                    dpid1_port = other_isl[dp_id1]
                                    opposite = self.opposite_link(dp_id1, dpid1_port)
                                    if opposite is not None:
                                        opposite_rem = opposite.keys()[0]
                                        if opposite_rem == remote_dpid:
                                            opposite_dpid_port = opposite[opposite_rem]
                                            path = [(dp_id1, dpid1_port, remote_dpid, opposite_dpid_port),
                                                    (remote_dpid, remote_dpid_port, dp_id2, isl_port)]
                                            return path

            return None

    def update_isl(self, dp_id, dp_port, isl_label, interswitch_links):
        if (dp_id, dp_port) in self.isl:
            del self.isl[(dp_id, dp_port)]

        self.isl[(dp_id, dp_port)] = (isl_label, interswitch_links)

        log.info("ISL table: %s", self.isl)

    def dp_port_to_fp_labels(self, dp_id, dp_port):
        try:
            return self.fastpaths[(dp_id, dp_port)]
        except KeyError:
            return (None, None, None, None)

    def dp_port_to_isl_labels(self, dp_id, dp_port):
        try:
            return self.isl[(dp_id, dp_port)]
        except KeyError:
            return None, None

    def fpentry_from_fplabel(self, fastpath_label):
        for dp_dets, fp_dets in self.fastpaths.items():
            label, vs_port, dp_fp_port, vs_fp_port = fp_dets
            if fastpath_label == label:
                return dp_dets, fp_dets
        dp_dets = (None, None)
        fp_dets = (None, None, None, None)
        return dp_dets, fp_dets

    def islentry_from_isllabel(self, isl_label):
        for dp_dets, isl_dets in self.isl.items():
            label, interswitch_links = isl_dets
            if isl_label == label:
                return dp_dets, isl_dets
        return None, None

    def fpentry_from_vs_port(self, virtual_port):
        for dp_dets, fp_dets in self.fastpaths.items():
            label, vs_port, dp_fp_port, vs_fp_port = fp_dets
            if virtual_port == vs_port:
                return dp_dets, fp_dets
        dp_dets = (None, None)
        fp_dets = (None, None, None, None)
        return dp_dets, fp_dets

    def dp_port_to_vs_port(self, dp_id, dp_port, dp_port_name,
                           dp_port_hw_addr):
        try:
            return self.dp_to_vs[(dp_id, dp_port, dp_port_name,
                                  dp_port_hw_addr)]
        except KeyError:
            return None

    def vs_port_to_dp_port(self, vs_port_name, vs_port, vs_port_hw_addr):
        try:
            return self.vs_to_dp[(vs_port_name, vs_port, vs_port_hw_addr)]
        except KeyError:
            return None

    def delete_port(self, dp_id, dp_port):
        for (id_, port, port_name, port_hw_addr) in self.dp_to_vs.keys():
            if (id_ == dp_id) and (port == dp_port):
                del self.dp_to_vs[(id_, port, port_name, port_hw_addr)]

            for key in self.vs_to_dp.keys():
                id_, port, port_name, port_hw_addr = self.vs_to_dp[key]
                if(id_ == dp_id) and (port == dp_port):
                    del self.vs_to_dp[key]

            for (id_, port) in self.fastpaths.keys():
                if (id_ == dp_id) and (port == dp_port):
                    del self.fastpaths[(id_, port)]

            for (id_, port) in self.isl.keys():
                if (id_ == dp_id) and (port == dp_port):
                    del self.isl[(id_, port)]

    def delete_dp(self, dp_id):
        for (id_, port, port_name, port_hw_addr) in self.dp_to_vs.keys():
            if id_ == dp_id:
                del self.dp_to_vs[(id_, port, port_name, port_hw_addr)]

        for key in self.vs_to_dp.keys():
            id_, port, port_name, port_hw_addr = self.vs_to_dp[key]
            if id_ == dp_id:
                del self.vs_to_dp[key]

        for (id_, port) in self.fastpaths.keys():
            if id_ == dp_id:
                del self.fastpaths[(id_, port)]

        for (id_, port) in self.isl.keys():
            if id_ == dp_id:
                del self.isl[(id_, port)]

        if dp_id in self.dp_dec_ttl:
            del self.dp_dec_ttl[dp_id]

        if dp_id in self.fastpath_switch:
            del self.fastpath_switch[dp_id]


class VSInterfaceManager(object):
    ''' VSInterfaceManager class handles the configuration of the virtual
        switch, the creation and removal of ports on the virtual switch
        based on datapath ports that would be used for forwarding.
    '''
    def __init__(self, *args, **kwargs):
        self.ovs = 'ovs-vsctl'
        self.ovsdb = '--db=unix:/var/run/openvswitch/db.sock'
        self.ofctl = 'ovs-ofctl'
        self.protocols = '--protocols=OpenFlow13'
        list_out = subprocess.check_output([self.ovs, self.ovsdb, 'list-br'])
        log.info("List of bridges on VM obtained")
        bridges = list_out.split()
        VSNL = IPRoute()
        if 'dp0' in bridges:
            subprocess.call([self.ovs, self.ovsdb, 'set', 'bridge',
                             'dp0', 'protocols=OpenFlow13'])
            subprocess.call([self.ovs, self.ovsdb, 'set-controller', 'dp0',
                             'tcp:127.0.0.1:6633'])
            subprocess.call([self.ovs, self.ovsdb, 'set', 'bridge', 'dp0',
                             'other-config:datapath-id=7266767372667673'])
            subprocess.call([self.ovs, self.ovsdb, 'set', 'bridge', 'dp0',
                             'other-config:disable-in-band=true'])
            port_output = subprocess.check_output([self.ovs, self.ovsdb,
                                                   'list-ports', 'dp0'])
            dpports = port_output.split()
            if not dpports:
                log.info("There are no existing ports on Virtual switch dp0")
            else:
                for dpport in dpports:
                    subprocess.check_call([self.ovs, self.ovsdb, 'del-port',
                                           'dp0', dpport])
                    if 'veth' in dpport:
                        subprocess.check_call(['ip', 'link', 'del', dpport])
                log.info("Deleted existing ports on bridge dp0")

        else:
            log.info("Virtual switch dp0 does not exist on this machine, adding...")
            ifaces = [x.get_attr('IFLA_IFNAME') for x in VSNL.get_links()]
            for iface in ifaces:
                if 'veth' in iface:
                    subprocess.check_call(['ip', 'link', 'del', iface])
            subprocess.check_call([self.ovs, self.ovsdb, 'add-br', 'dp0'])
            subprocess.check_call([self.ovs, self.ovsdb, 'set', 'bridge',
                                   'dp0', 'protocols=OpenFlow13'])
            subprocess.check_call([self.ovs, self.ovsdb, 'set', 'bridge',
                                   'dp0', 'other-config:disable-in-band=true'])
            subprocess.check_call([self.ovs, self.ovsdb, 'set-controller',
                                   'dp0', 'tcp:127.0.0.1:6633'])
            subprocess.check_call([self.ovs, self.ovsdb,
                                   'set', 'bridge', 'dp0',
                                   'other-config:datapath-id=7266767372667673'])
            log.info("Virtual switch dp0 set up complete !!!")

    def AddPort(self, switchName, Port_No):
        dp_veth = ''.join(['veth', '-', switchName[:3], '-', str(Port_No)])
        vs_port_name = ''.join([switchName, str(Port_No)])
        vs_ofp_no = 50 + Port_No
        set_ofp_no = 'ofport_request'+'='+str(vs_ofp_no)
        AddLink = subprocess.call(['ip', 'link', 'add', dp_veth, 'type',
                                         'veth', 'peer', 'name', vs_port_name])
        if AddLink != 0:
            try:
                subprocess.check_call(['ifconfig', dp_veth])
            except subprocess.CalledProcessError:
                log.error("Fatal Error!!! Port name:%s, No:%s not created, Quitting",
                          vs_port_name, vs_ofp_no)
                traceback.print_exc(file=sys.stdout)
                sys.exit(1)
        try:
            subprocess.check_call([self.ovs, self.ovsdb, 'add-port', 'dp0',
                                   dp_veth, '--', 'set', 'interface',
                                   dp_veth, set_ofp_no])
            log.info("Port: %s added to bridge dp0", vs_port_name)
        except subprocess.CalledProcessError:
            log.error("Fatal Error!!! Port name:%s, No:%s not added to virtual switch dp0, Quitting",
                      vs_port_name, vs_ofp_no)
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)
        vsdevices.append(vs_port_name)
        subprocess.check_call(['ip', 'link', 'set', vs_port_name, 'up'])
        subprocess.check_call(['ip', 'link', 'set', dp_veth, 'up'])
        return vs_port_name, vs_ofp_no

    def SetIPAddress(self, PortName, addresses):
        for address in addresses:
            try:
                subprocess.check_call(['ip', 'addr', 'add', address,
                                       'dev', PortName])
                log.info("Added address %s to interface %s", address, PortName)
            except subprocess.CalledProcessError:
                log.error("Error while adding %s to interface %s",
                          address, PortName)
                traceback.print_exc(file=sys.stdout)
                sys.exit(1)

    def DelPort(self, switchName, Port_No):
        dp_veth = ''.join(['veth', '-', switchName[:3], '-', str(Port_No)])
        vs_port_name = ''.join([switchName, str(Port_No)])
        DelLink = subprocess.call(['ip', 'link', 'del', vs_port_name])
        if DelLink != 0:
            try:
                subprocess.check_call(['ifconfig', dp_veth])
                log.error("Interface %s not deleted from virtual switch dp0")
                sys.exit(1)
            except subprocess.CalledProcessError:
                pass
        else:
            try:
                subprocess.check_call([self.ovs, self.ovsdb, 'del-port', 'dp0',
                                       dp_veth])
                vsdevices.remove(vs_port_name)
                log.info("Port: %s deleted from bridge dp0", vs_port_name)
            except subprocess.CalledProcessError:
                log.error("Error!!! Port name:%s was not deleted from virtual switch dp0",
                          vs_port_name)
                traceback.print_exc(file=sys.stdout)
                sys.exit(1)

    def AddFastPath(self, fp_int_name, fp_ofp_no):
        log.info("Setting up the fastpath interface on dp0")
        set_ofp_no = 'ofport_request'+'='+str(fp_ofp_no)
        try:
            subprocess.check_call([self.ovs, self.ovsdb, 'add-port', 'dp0',
                                   fp_int_name, '--', 'set', 'interface',
                                   fp_int_name, set_ofp_no])
            log.info("Port %s with OpenFlow Port number %s  added to dp0",
                     fp_int_name, fp_ofp_no)
        except subprocess.CalledProcessError:
            log.error("Unsuccessful setup for FastPath interface on dp0")
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

    def CleanUp(self):
        log.info("Removing bridge dp0 ...")
        subprocess.call([self.ovs, self.ovsdb, 'del-br', 'dp0'])
        log.info("Bridge dp0 removed")

    def vsinterfacedelete(self, vs_int_name):
        try:
            subprocess.check_call(['ip', 'link', 'del', vs_int_name])
            log.info("Interfaces %s deleted", vs_int_name)
        except subprocess.CalledProcessError:
            log.error("Error, interface delete failed")
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)


class RheaController(app_manager.RyuApp):
    ''' RheaFlow's main application, the logic of RheaFlow application
        is implemented here.
    '''
    _CONTEXTS = {'switches': switches.Switches, 'netlink': RheaNLSocket,
                 'RouteReceiver': RheaRouteReceiver}
    OFP_VERSIONS = [ofproto.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RheaController, self).__init__(*args, **kwargs)

        self.VSManager = VSInterfaceManager()
        self.switches = kwargs['switches']
        self.receiver = kwargs['RouteReceiver']
        self.yamlObj = RheaYAML(config_file)
        self.table = Table()
        self.labeller = MetaVLAN()
        self.pendingroute = []
        self.vsif_to_ofp = {}
        self.netlink = kwargs['netlink']
        self.flowprocessor = RheaFlowProcessor(self.switches)
        self.all_fp_entries = self.yamlObj.fetch_fastpath_entries()
        log.info("RYU RheaController running.")
        self.threads.append(hub.spawn(self.retry_pendingroutes))
        self.dp_entries = []
        self.isl_switches = []
        self.fastpath_configured = False

    def configure_datapath(self, dp, dp_id, vs_port_prefix, dp_entry):
        ofports_in_dp_entry = dp_entry['ports']
        dp_fastpath_port = self.yamlObj.fetch_fpport(dp_entry)
        vs_fastpath_port = self.yamlObj.fetch_vsfpport(dp_entry)
        interswitch_links = self.yamlObj.fetch_interswitch_links(dp_entry)

        if ((dp_fastpath_port is not None) and
                (vs_fastpath_port is not None)):
            self.table.set_fastpath_switch(dpid_to_str(dp_id),
                                           dp_fastpath_port,
                                           vs_fastpath_port)
            self.fastpath_configured = True

        if (interswitch_links is not None):
            if not self.table.fastpath_switch:
                self.isl_switches.append([dp_entry, dp_id, vs_port_prefix])
                return

        if len(ofports_in_dp_entry) != 0:
            for ofp_no, addresses in ofports_in_dp_entry.items():
                ofport = self.switches._get_port(dp_id, ofp_no)
                if ofport is not None:
                    port_name = ofport.name
                    port_hw_addr = ofport.hw_addr
                    vs_port_name, vs_port_no = self.VSManager.AddPort(vs_port_prefix, ofp_no)
                    time.sleep(.10)
                    self.VSManager.SetIPAddress(vs_port_name, addresses)
                    vs_interface = self.netlink.find_interface_by_name(vs_port_name)

                    if vs_interface:
                        vs_port_hw_addr = vs_interface['mac-address']
                        vs_ifindex = vs_interface['ifindex']
                        self.vsif_to_ofp[vs_ifindex] = vs_port_no
                    else:
                        log.error("Virtual switch interface not found, Mapping not completed, %s not found in interface table",
                                  vs_port_name)
                        traceback.print_exc(file=sys.stdout)
                        self.shutdown(1)
                    log.info("Virtual switch Port %s with OpenFlow port number %s has a mac address of %s",
                             vs_port_name, vs_port_no, vs_port_hw_addr)

                    self.table.update_dp_port(dpid_to_str(dp_id),
                                              ofp_no, port_name,
                                              port_hw_addr,
                                              vs_port_name,
                                              vs_port_no,
                                              vs_port_hw_addr)
                    log.info("OpenFlow port %d on dp_id=%s added to dp0",
                             ofp_no, dpid_to_str(dp_id))

                    if ((dp_fastpath_port is not None) and
                       (vs_fastpath_port is not None)):

                        fp_label = self.labeller.allocate_label()
                        self.table.update_fastpath(dpid_to_str(dp_id),
                                                   ofp_no, fp_label,
                                                   vs_port_no,
                                                   dp_fastpath_port,
                                                   vs_fastpath_port)

                        self.flowprocessor.vs_fastpath_flows(fp_label,
                                                             vs_fastpath_port,
                                                             vs_port_no)

                        self.flowprocessor.fastpath_flows(dp, fp_label,
                                                          ofp_no,
                                                          dp_fastpath_port,
                                                          vs_port_hw_addr)
                        log.info("FastPath is enabled, allocating label:%s for port %s on dpid:%s to port %s on the virtual switch using link (dpid:%s,port:%s)->(VS,port:%s)",
                                 fp_label, ofp_no, dpid_to_str(dp_id),
                                 vs_port_no, dpid_to_str(dp_id),
                                 dp_fastpath_port, vs_fastpath_port)
                    else:
                        log.info("FastPath is not enabled for port %s on (dpid:%s)", ofp_no,
                                 dpid_to_str(dp_id))

                    if (interswitch_links is not None):
                        isl_label = self.labeller.allocate_label()
                        self.table.update_isl(dpid_to_str(dp_id),
                                              ofp_no, isl_label,
                                              interswitch_links)
                        self.flowprocessor.ingress_isl_flows(dp, isl_label,
                                                             ofp_no, interswitch_links)
                        if self.table.fastpath_switch:
                            fastpath_dpid = self.table.fastpath_switch.keys()[0]
                            dp_fs_port, vs_fs_port = self.table.fastpath_switch[fastpath_dpid]
                            if fastpath_dpid is not dpid_to_str(dp_id):
                                for isl_port, remote_dp in interswitch_links.items():
                                    remote_dpid = remote_dp.keys()[0]
                                    remote_dpid_port = remote_dp[remote_dpid]
                                    if remote_dpid == fastpath_dpid:
                                        self.flowprocessor.vs_fastpath_flows(isl_label,
                                                                             vs_fs_port,
                                                                             vs_port_no)
                                        fastpath_switch = self.switches._get_switch(str_to_dpid(fastpath_dpid))
                                        fastpath_dp = fastpath_switch.dp
                                        self.flowprocessor.egress_isl_flows(fastpath_dp,
                                                                            isl_label,
                                                                            remote_dpid_port,
                                                                            dp_fs_port)
                                        self.flowprocessor.fastpath_flows(dp, isl_label,
                                                                          ofp_no,
                                                                          isl_port,
                                                                          vs_port_hw_addr)
                        log.info("Inter-switch link is enabled, allocationg label:%s for port %s on dpid:%s.",
                                 isl_label, ofp_no, dpid_to_str(dp_id))
                    else:
                        log.info("Inter-switch link is not enabled for port:%s on (dpid:%s)",
                                 ofp_no, dpid_to_str(dp_id))
                    if ((dp_fastpath_port is None) and
                            (vs_fastpath_port is None) and
                            (interswitch_links is None)):
                        self.flowprocessor.create_initial_flow(dp,
                                                               vs_port_hw_addr,
                                                               ofp_no)
                else:
                    log.warn("There are no ports to be mapped for (dp_id=%s) in config",
                             dpid_to_str(dp_id))

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def handler_datapath_enter(self, ev):
        dp = ev.switch.dp
        dp_id = dp.id

        log.info("INFO:RheaController:Datapath is up (dp_id=%s)",
                 dpid_to_str(dp_id))
        self.flowprocessor.clear_flows(dp)
        if not is_rfvs(dp_id):
            dp_entry = self.yamlObj.get_dp_entry(self.yamlObj.configs,
                                                 dpid_to_str(dp_id))
            if dp_entry is not None:
                log.info("INFO:configuring flow tables and installing initial rules on datapath (dp_id=%s)",
                         dpid_to_str(dp_id))

                vs_port_prefix = self.yamlObj.get_vs_port_prefix(self.yamlObj.configs,
                                                                 dpid_to_str(dp_id))
                decrement_ttl = self.yamlObj.dec_ttl_set(self.yamlObj.configs,
                                                         dpid_to_str(dp_id))
                self.table.update_dp_dec_ttl(dpid_to_str(dp_id), decrement_ttl)
                if vs_port_prefix is None:
                    vs_port_prefix = 'dpid'+str(int(dpid_to_str(dp_id), 16))+'-p'

                try:
                    ofports_in_dp_entry = dp_entry['ports']
                except KeyError:
                    log.error("No 'ports' field was found in the config for (dp_id=%s)",
                              dpid_to_str(dp_id))
                    traceback.print_exc(file=sys.stdout)
                    self.shutdown(1)

                vswitch = self.switches._get_switch(str_to_dpid(vs_id))
                if vswitch is None:
                    self.dp_entries.append([dp_entry, dp_id, vs_port_prefix])
                    return

                self.configure_datapath(dp, dp_id, vs_port_prefix, dp_entry)
                if self.fastpath_configured is True:
                    if len(self.isl_switches) != 0:
                        for isl_switch in self.isl_switches:
                            dp_entry = isl_switch[0]
                            dp_id = isl_switch[1]
                            vs_port_prefix = isl_switch[2]
                            ofports_in_dp_entry = dp_entry['ports']
                            switch = self.switches._get_switch(dp_id)
                            datapath = switch.dp
                            self.configure_datapath(datapath, dp_id, vs_port_prefix, dp_entry)
                        self.isl_switches = []
        else:
            if len(self.dp_entries) != 0:
                for entry in self.dp_entries:
                    dp_entry = entry[0]
                    dp_id = entry[1]
                    vs_port_prefix = entry[2]
                    ofports_in_dp_entry = dp_entry['ports']
                    switch = self.switches._get_switch(dp_id)
                    datapath = switch.dp
                    self.configure_datapath(datapath, dp_id, vs_port_prefix, dp_entry)
                self.dp_entries = []

            if self.fastpath_configured is True:
                if len(self.isl_switches) != 0:
                    for isl_switch in self.isl_switches:
                        dp_entry = isl_switch[0]
                        dp_id = isl_switch[1]
                        vs_port_prefix = isl_switch[2]
                        ofports_in_dp_entry = dp_entry['ports']
                        switch = self.switches._get_switch(dp_id)
                        datapath = switch.dp
                        self.configure_datapath(datapath, dp_id, vs_port_prefix, dp_entry)
                    self.isl_switches = []

            vs_fastpath_int, vs_fastpath_port = self.yamlObj.vs_fp_entry()
            if ((vs_fastpath_int is None) and (vs_fastpath_port is None) and
                    (self.table.fastpaths is not None)):
                log.warn("No interface was designated for FastPath on the virtual switch")
                self.flowprocessor.create_initial_flow(dp)
            else:
                vs_iface = self.netlink.find_interface_by_name(vs_fastpath_int)
                if vs_iface is None:
                    log.error("Interface %s not found!!!",
                              vs_fastpath_int)
                    self.shutdown(1)
                self.VSManager.AddFastPath(vs_fastpath_int, vs_fastpath_port)

        log.info("Bringing up interfaces added to virtual switch")
        for iface in self.netlink.ifaceTable:
            if iface['state'] != 'UP':
                ifname = iface['ifname']
                subprocess.call(['ip', 'link', 'set', ifname, 'up'])

    @set_ev_cls(RheaFlowEvents.EventRouterConnect)
    def handler_router_connect(self, ev):
        log.info("Event is %s", ev)
        routerid = ev.routerid
        log.info("Router with address %s has connected with port %s",
                 routerid[0], routerid[1])

    @set_ev_cls(RheaFlowEvents.EventNeighbourNotify)
    def neighbour_handler(self, ev):
        '''Handles neigbour added or removed'''
        event = ev.action
        neighbour = ev.neighbour
        vsindex = neighbour['ifindex']
        if vsindex in self.vsif_to_ofp:
            vs_ofport = self.vsif_to_ofp[vsindex]
            vs_interface = self.netlink.find_interface(vsindex)
            if event == 'RTM_NEWNEIGH':
                self.flowprocessor.new_dphost_add_flow(neighbour,
                                                       self.table,
                                                       vs_interface,
                                                       vs_ofport)
            elif event == 'RTM_DELNEIGH':
                vs_interface = self.netlink.find_interface(vsindex)
                if vs_interface is None:
                    return
                self.flowprocessor.delete_host_flow(neighbour, self.table,
                                                    vs_interface, vs_ofport)
            else:
                log.info("Neigbour event %s happened", event)

    @set_ev_cls(RheaFlowEvents.EventRouterDisconnect)
    def handler_router_disconnect(self, ev):
        log.info("Event is %s", ev)
        routerid = ev.routerid
        log.info("Router with address %s connected with port %s is\
                 disconnecting", routerid[0], routerid[1])

    @set_ev_cls(RheaFlowEvents.EventRouteDeleted)
    def handler_remove_route(self, ev):
        ''' Event handler for deleting rules for
            the route that is been deleted.
        '''
        route = ev.route
        next_hop = route[1]
        nh_interface = self.netlink.find_interface_by_ip(next_hop)
        if nh_interface is None:
            nh_host = self.netlink.ip_host_lookup(next_hop)
            if nh_host is not None:
                self.flowprocessor.delete_flows(route, self.table,
                                                self.netlink.ifaceTable,
                                                self.netlink.neighbours,
                                                self.vsif_to_ofp,
                                                host=nh_host)
            else:
                pass
        else:
            self.flowprocessor.delete_flows(route, self.table,
                                            self.netlink.ifaceTable,
                                            self.netlink.neighbours,
                                            self.vsif_to_ofp,
                                            interface=nh_interface)

    @set_ev_cls(RheaFlowEvents.EventRouteReceived)
    def handler_route_received(self, ev):
        ''' Event handler for converting routes received
            from router into OpenFlow rules.
        '''
        route = ev.route
        next_hop = route[1]
        nh_interface = self.netlink.find_interface_by_ip(next_hop)
        if nh_interface is None:
            nh_host = self.netlink.ip_host_lookup(next_hop)
            if nh_host is None:
                if next_hop in self.netlink.unresolvedneighbours:
                    log.error("%s is unreachable, flow cannot be installed!!!",
                              next_hop)
                else:
                    self.netlink.NeighbourDiscovery(next_hop)
                    self.pendingroute.append(route)
                    log.info("Adding %s to pending route table", route)
            else:
                self.flowprocessor.convert_route_to_flow(route, self.table,
                                                         self.netlink.ifaceTable,
                                                         self.netlink.neighbours,
                                                         self.vsif_to_ofp,
                                                         host=nh_host)
        else:
            self.flowprocessor.convert_route_to_flow(route, self.table,
                                                     self.netlink.ifaceTable,
                                                     self.netlink.neighbours,
                                                     self.vsif_to_ofp,
                                                     interface=nh_interface)

    def retry_pendingroutes(self):
        for route in self.pendingroute:
            next_hop = route[1]
            nh_host = self.netlink.ip_host_lookup(next_hop)
            if nh_host is not None:
                self.flowprocessor.convert_route_to_flow(route, self.table,
                                                         self.netlink.ifaceTable,
                                                         self.netlink.neighbours,
                                                         self.vsif_to_ofp,
                                                         host=nh_host)
                self.pendingroute = list(filter(lambda x: x != route,
                                         self.pendingroute))
            else:
                if next_hop in self.netlink.unresolvedneighbours:
                    log.error("%s is unreachable, flow cannot be installed!!!",
                              next_hop)
        hub.sleep(600)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        ''' Event handler for processing packet-ins received
            by the controller from connected OpenFlow datapaths.
        '''
        msg = ev.msg
        self.flowprocessor.handle_packet_in(msg, self.table,
                                            self.netlink.ifaceTable,
                                            self.vsif_to_ofp,
                                            self.netlink.neighbours)

    @set_ev_cls(event.EventPortDelete)
    def OFPort_DELETE(self, ev):
        ''' This event handler reconfigures dp0 and the OpenFlow
            datapaths in response to a port removal on connected
            OpenFlow datapaths.
        '''
        Port = ev.port
        dpid = Port.dpid
        port_no = Port.port_no
        port_name = Port.name
        port_hw_addr = Port.hw_addr

        log.info("Port %s removed from dpid %s", port_no, dpid_to_str(dpid))
        if not is_rfvs(dpid):
            dp_entry = self.yamlObj.get_dp_entry(self.yamlObj.configs,
                                                 dpid_to_str(dpid))
            if dp_entry is not None:
                vs_port_prefix = self.yamlObj.get_vs_port_prefix(self.yamlObj.configs,
                                                                 dpid_to_str(dpid))
                if vs_port_prefix is None:
                    vs_port_prefix = 'dpid'+str(int(dpid_to_str(dpid), 16))+'-p'

                ofports_in_dp_entry = dp_entry['ports']
                if port_no in ofports_in_dp_entry:
                    dp_to_vs = self.table.dp_port_to_vs_port(dpid_to_str(dpid),
                                                             port_no, port_name,
                                                             port_hw_addr)
                    vs_port_name, vs_port, vs_port_hw_addr = dp_vs_map
                    for vsindex, vsport in self.vsif_to_ofp.items():
                        if vsport == vs_port:
                            del self.vsif_to_ofp[vsindex]
                    self.VSManager.DelPort(vs_port_prefix, port_no)
                    self.table.delete_port(dpid_to_str(dpid), port_no)
                    log.info("virtual interfaces index to OpenFlow port number map:%s",
                             self.vsif_to_ofp)
                    log.info("dp_to_vs table: %s", self.table.dp_to_vs)
                    log.info("vs_to_dp table: %s", self.table.vs_to_dp)

    @set_ev_cls(event.EventPortAdd)
    def OFPort_ADD(self, ev):
        ''' Reconfigures dp0 and the OpenFlow datapaths in response
            to newly added ports.
        '''
        Port = ev.port
        dpid = Port.dpid
        switch = self.switches._get_switch(dpid)
        dp = switch.dp
        port_no = Port.port_no
        port_name = Port.name
        port_hw_addr = Port.hw_addr
        log.info("Port %s added to dpid %s", port_no, dpid_to_str(dpid))
        if not is_rfvs(dpid):
            dp_entry = self.yamlObj.get_dp_entry(self.yamlObj.configs,
                                                 dpid_to_str(dpid))
            if dp_entry is not None:
                vs_port_prefix = self.yamlObj.get_vs_port_prefix(self.yamlObj.configs,
                                                                 dpid_to_str(dpid))
                if vs_port_prefix is None:
                    vs_port_prefix = 'dpid'+str(int(dpid_to_str(dpid), 16))+'-p'
                ofports_in_dp_entry = dp_entry['ports']
                if port_no in ofports_in_dp_entry:
                    vs_port_name, vs_port_no = self.VSManager.AddPort(vs_port_prefix, port_no)
                    time.sleep(.10)
                    addresses = ofports_in_dp_entry[port_no]
                    self.VSManager.SetIPAddress(vs_port_name, addresses)
                    vs_interface = self.netlink.find_interface_by_name(vs_port_name)
                    if vs_interface:
                        vs_port_hw_addr = vs_interface['mac-address']
                        vs_ifindex = vs_interface['ifindex']
                        self.vsif_to_ofp[vs_ifindex] = vs_port_no
                    else:
                        log.error("Virtual switch interface not found, Mapping not completed,%s not found in interface table",
                                  vs_port_name)
                        self.shutdown(1)
                    log.info("Virtual switch port %s with OpenFlow port number %s has a mac address of %s",
                             vs_port_name, vs_port_no, vs_port_hw_addr)
                    self.table.update_dp_port(dpid_to_str(dpid), port_no,
                                              port_name, port_hw_addr,
                                              vs_port_name, vs_port_no,
                                              vs_port_hw_addr)
                    log.info("OpenFlow port %d on dp_id=%s added to virtual switch", port_no,
                             dpid_to_str(dpid))
                    dp_fastpath_port = self.yamlObj.fetch_fpport(dp_entry)
                    vs_fastpath_port = self.yamlObj.fetch_vsfpport(dp_entry)
                    interswitch_links = self.yamlObj.fetch_interswitch_links(dp_entry)
                    if ((dp_fastpath_port is not None) and
                            (vs_fastpath_port is not None)):
                        fp_label = self.labeller.allocate_label()
                        self.table.update_fastpath(dpid_to_str(dpid), port_no,
                                                   fp_label, vs_port_no,
                                                   dp_fastpath_port,
                                                   vs_fastpath_port)
                        self.flowprocessor.vs_fastpath_flows(fp_label,
                                                             vs_fastpath_port,
                                                             vs_port_no)
                        self.flowprocessor.fastpath_flows(dp, fp_label,
                                                          port_no,
                                                          dp_fastpath_port,
                                                          vs_port_hw_addr)
                        log.info("FastPath is enabled, allocating label:%s for port %s on dpid:%s to port %s on the virtual switch using link (dpid:%s,port:%s)->(VS,port:%s)",
                                 fp_label, port_no, dpid_to_str(dpid),
                                 vs_port_no, dpid_to_str(dpid),
                                 dp_fastpath_port, vs_fastpath_port)
                    else:
                        log.info("FastPath is not enabled for port %s on (dpid:%s)",
                                 port_no, dpid_to_str(dpid))

                    if (interswitch_links is not None):
                        isl_label = self.labeller.allocate_label()
                        self.table.update_isl(dpid_to_str(dpid), port_no,
                                              isl_label, interswitch_links)
                        self.flowprocessor.ingress_isl_flows(dp, isl_label, port_no,
                                                             interswitch_links)
                        if self.table.fastpath_switch:
                            fastpath_dpid = self.table.fastpath_switch.keys()[0]
                            dp_fs_port, vs_fs_port = self.table.fastpath_switch[fastpath_dpid]
                            if fastpath_dpid is not dpid_to_str(dpid):
                                for isl_port, remote_dp in interswitch_links.items():
                                    remote_dpid = remote_dp.keys()[0]
                                    remote_dpid_port = remote_dp[remote_dpid]
                                    if remote_dpid == fastpath_dpid:
                                        self.flowprocessor.vs_fastpath_flows(isl_label,
                                                                             vs_fs_port,
                                                                             vs_port_no)
                                        fastpath_switch = self.switches._get_switch(str_to_dpid(fastpath_dpid))
                                        fastpath_dp = fastpath_switch.dp
                                        self.flowprocessor.egress_isl_flows(fastpath_dp,
                                                                            isl_label,
                                                                            remote_dpid_port,
                                                                            dp_fs_port)
                                        self.flowprocessor.fastpath_flows(dp, isl_label,
                                                                          port_no,
                                                                          isl_port,
                                                                          vs_port_hw_addr)

                        log.info("Inter-switch link is enabled, allocating label:%s for port %s on dpid:%s)",
                                 isl_label, port_no, dpid_to_str(dpid))
                    else:
                        log.info("Inter-switch link is not enabled for port:%s on (dpid:%s)",
                                 port_no, dpid_to_str(dpid))

                    if ((dp_fastpath_port is None) and
                            (vs_fastpath_port is None) and
                            (interswitch_links is None)):
                        self.flowprocessor.create_initial_flow(dp,
                                                               vs_port_hw_addr,
                                                               port_no)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def handler_datapath_leave(self, ev):
        ''' Handles operations for when an OpenFlow datapath
            disconnects from the controller.
        '''
        dp = ev.switch.dp
        dp_id = dp.id
        log.info("INFO:RheaController:Datapath is down (dp_id=%s)",
                 dpid_to_str(dp_id))
        if not is_rfvs(dp_id):
            dp_entry = self.yamlObj.get_dp_entry(self.yamlObj.configs,
                                                 dpid_to_str(dp_id))
            self.table.delete_dp(dpid_to_str(dp_id))
            if dp_entry is not None:
                vs_port_prefix = self.yamlObj.get_vs_port_prefix(self.yamlObj.configs,
                                                                 dpid_to_str(dp_id))
                if vs_port_prefix is None:
                    vs_port_prefix = 'dpid'+str(int(dpid_to_str(dp_id), 16))+'-p'
                ofports_in_dp_entry = dp_entry['ports']
                if len(ofports_in_dp_entry) != 0:
                    for ofp_no in ofports_in_dp_entry:
                        vs_port = 50 + ofp_no
                        for vsindex, vsport in self.vsif_to_ofp.items():
                            if vsport == vs_port:
                                del self.vsif_to_ofp[vsindex]
                        self.VSManager.DelPort(vs_port_prefix, ofp_no)
                        log.info("dp_to_vs table: %s", self.table.dp_to_vs)
                        log.info("vs_to_dp table: %s", self.table.vs_to_dp)
                        log.info("Port %d on dp_id=%s unmapped from virtual switch",
                                 ofp_no, dpid_to_str(dp_id))
        else:
            log.error("Virtual switch 'dp0' is down!!! Restart RheaFlow")
            self.shutdown(1)

    def shutdown(self, exit_status):
        ''' 1 - Abnormal shutdown
            0 - Normal shutdown
        '''
        self.stop()
        if exit_status == 1:
            sys.exit(1)
            log.info("RheaFlow shutdown abnormally")
        else:
            sys.exit(0)

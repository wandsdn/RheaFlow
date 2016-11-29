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

import os
import socket
import select
from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from netaddr import IPAddress, IPNetwork
from RheaFlowEvents import EventNeighbourNotify
from log import log
try:
    import cPickle as pickle
except:
    import pickle


class RheaNLSocket(app_manager.RyuApp):

    _EVENTS = [EventNeighbourNotify]

    def __init__(self):
        super(RheaNLSocket, self).__init__()
        self.name = 'RheaNLSocket'
        self.server_host = os.environ.get('RHEA_NETLINK_LISTENER', '0.0.0.0')
        self.server_port = int(os.environ.get('RHEA_NETLINK_LISTENER', 55651))
        self.neighbours = []
        self.unresolvedneighbours = []
        self.ifaceTable = []
        self._stop = False

    def start(self):
        super(RheaNLSocket, self).start()
        log.debug("Netlink socket server listening on %s:%s", self.server_host,
                  self.server_port)
        server_addr = ('localhost', 55652)
        inisock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        inisock.connect(server_addr)
        request = pickle.dumps(['ifaceTable'])
        inisock.send(request)
        msg = inisock.recv(8192)
        if msg != 'None':
            data = pickle.loads(msg)
            self.ifaceTable = data[1]
        request = pickle.dumps(['neighbourtable'])
        inisock.send(request)
        msg = inisock.recv(8192)
        if msg != 'None':
            data = pickle.loads(msg)
            self.neighbours = data[1]
        request = pickle.dumps(['get_unresolved'])
        inisock.send(request)
        msg = inisock.recv(8192)
        if msg != 'None':
            data = pickle.loads(msg)
            self.unresolvedneighbours = data[1]
        inisock.close()
        for iface in self.ifaceTable:
            log.info("Interface %s has address %s", iface['ifname'],
                     iface['mac-address'])
        return hub.spawn(StreamServer((self.server_host, self.server_port),
                         self.loop).serve_forever)

    def nl_response(self, sock, is_active):
        response = pickle.dumps('Accepted')
        try:
            sock.send(response)
        except socket.error as e:
            is_active = False

    def loop(self, sock, addr):
        if self._stop is False:
            is_active = True
        else:
            is_active = False

        while is_active:
            received = sock.recv(8192)
            if len(received) == 0:
                is_active = False
                break
            data = pickle.loads(received)
            if data != 'None':
                if data[0] == 'add_neigh':
                    self.neighbours.append(data[1])
                    self.send_event_to_observers(EventNeighbourNotify(data[1],
                                                 'RTM_NEWNEIGH'))
                elif data[0] == 'remove_neigh':
                    self.neighbours = list(filter(lambda x: x != data[1],
                                           self.neighbours))
                    self.send_event_to_observers(EventNeighbourNotify(data[1],
                                                 'RTM_DELNEIGH'))
                elif data[0] == 'ifaceTable':
                    self.ifaceTable = data[1]
                elif data[0] == 'neighbourtable':
                    self.neighbours = data[1]
                elif data[0] == 'unresolved':
                    self.unresolvedneighbours = data[1]
                else:
                    pass
            self.nl_response(sock, is_active)
        sock.shutdown(socket.SHUT_RDWR)
        log.info("Netlink supplier died")

    def poll_netlink(self):
        poll = select.poll()
        poll.register(self.sock, select.POLLIN | select.POLLPRI)
        sockfd = self.sock.fileno()
        while True:
            hub.sleep(2)
            events = poll.poll()
            for (fd, event) in events:
                if fd == sockfd:
                    msg = self.sock.recv(8192)
                    data = pickle.loads(msg)
                    if data != 'None':
                        if data[0] == 'add_neigh':
                            self.neighbours.append(data[1])
                            self.send_event_to_observers(EventNeighbourNotify(
                                                         data[1],
                                                         'RTM_NEWNEIGH'))
                        elif data[0] == 'remove_neigh':
                            self.neighbours = list(filter(lambda x: x !=
                                                   data[1],
                                                   self.neighbours))
                            self.send_event_to_observers(EventNeighbourNotify(
                                                         data[1],
                                                         'RTM_DELNEIGH'))
                        elif data[0] == 'ifaceTable':
                            self.ifaceTable = data[1]
                        elif data[0] == 'neighbourtable':
                            self.neighbours = data[1]
                        elif data[0] == 'unresolved':
                            self.unresolvedneighbours = data[1]
                        else:
                            pass

    def NeighbourDiscovery(self, addr):
        ip = IPAddress(addr)
        msg = "Hello, It's me"
        if ip.version == 4:
            dest_addr = (addr, 6666)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            try:
                sent = sock.sendto(msg, dest_addr)
            except socket.error as e:
                log.error("Sending discovery packet to %s failed with error\
                          %s", addr, os.strerror(e.errno))
                sock.close()
            sock.close()
        elif ip.version == 6:
            dest_addr = (addr, 6666)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setblocking(0)
            try:
                sent = sock.sendto(msg, dest_addr)
            except socket.error as e:
                log.error("Sending discovery packet to %s failed with error\
                          %s", addr, os.strerror(e.errno))
                sock.close()
            sock.close()
        else:
            log.error("Invalid address family for IP %s, Neighbour Discovery\
                      not initiated", addr)

    def find_interface(self, ifindex):
        for interface in self.ifaceTable:
            if ifindex == interface['ifindex']:
                return interface
        return None

    def find_by_interface_by_mac(self, mac_addr):
        for interface in self.ifaceTable:
            if mac_addr == interface['mac-address']:
                return interface
        return None

    def find_interface_by_ip(self, ip_addr):
        ipnet = IPNetwork(ip_addr)
        for interface in self.ifaceTable:
            address_list = interface['IP-Addresses']
            for address in address_list:
                (addr, mask) = address
                addrnet = IPNetwork(addr)
                if ipnet.ip == addrnet.ip:
                    return interface
        return None

    def find_interface_by_name(self, ifname):
        for interface in self.ifaceTable:
            if ifname == interface['ifname']:
                return interface
        return None

    def ip_host_lookup(self, ip_addr):
        ipnet = IPNetwork(ip_addr)
        for host in self.neighbours:
            hostaddr = host['ipaddr']
            hostnet = IPNetwork(hostaddr)
            if ipnet.ip == hostnet.ip:
                return host
        return None

    def mac_host_lookup(self, mac_addr):
        for host in self.neighbours:
            if mac_addr == host['mac_addr']:
                return host
        return None

    def shutdown(self):
        self.nl_request(['shutdown'])

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
# Name: NetlinkProcessor.py
# Author: Oladimeji Fayomi
# Created: 25 May 2016
# Last Modified: 17 August 2016
# Version: 1.0
# Description: Listens to netlink messages and notifies the RheaFlow
#              application of important netlink messages.

import socket
from pyroute2 import IPDB
import eventlet
from datetime import datetime
from log import log
try:
    import cPickle as pickle
except:
    import pickle


server_addr = ('127.0.0.1', 55651)


class NetlinkClient(object):
    def __init__(self):
        self.neighbours = []
        self.unresolvedneighbours = []
        self.ip = IPDB(ignore_rtables=[254])
        self.ip_uuid = self.ip.register_callback(self.callback)
        self.server = eventlet.listen(('127.0.0.1', 55652))
        self.socket = None
        self.serve = True
        self.pool = eventlet.GreenPool()
        self.not_connect = True

    def callback(self, ipdb, msg, action):
        if action is 'RTM_NEWNEIGH':
            self.add_neighbour(msg)
        if action is 'RTM_DELNEIGH':
            self.remove_neighbour(msg)
        if action is 'RTM_NEWLINK':
            self.notify(['ifaceTable', self.ifaceTable(ipdb)])
        if action is 'RTM_DELLINK':
            self.notify(['ifaceTable', self.ifaceTable(ipdb)])
        if action is 'RTM_NEWADDR':
            log.info("RTM_NEWADDR happened at %s", str(datetime.now()))
            self.notify(['ifaceTable', self.ifaceTable(ipdb)])
        if action is 'RTM_DELADDR':
            log.info("RTM_DELADDR happened at %s", str(datetime.now()))
            self.notify(['ifaceTable', self.ifaceTable(ipdb)])

    def add_neighbour(self, msg):
        attributes = msg['attrs']
        ip_addr = attributes[0][1]
        if attributes[1][0] is 'NDA_LLADDR':
            mac_addr = attributes[1][1]
            iface_index = msg['ifindex']
            host = {'ipaddr': ip_addr, 'mac_addr': mac_addr,
                    'ifindex': iface_index}
            if host not in self.neighbours:
                self.notify(['add_neigh', host])
                self.neighbours.append(host)
                if ip_addr in self.unresolvedneighbours:
                    self.unresolvedneighbours = list(filter(lambda x: x !=
                                                     ip_addr,
                                                     self.unresolvedneighbours)
                                                     )
        else:
            if ip_addr not in self.unresolvedneighbours:
                self.unresolvedneighbours.append(ip_addr)
                self.notify(['unresolved', self.unresolvedneighbours])

    def remove_neighbour(self, msg):
        attributes = msg['attrs']
        ip_addr = attributes[0][1]
        if attributes[1][0] is 'NDA_LLADDR':
            mac_addr = attributes[1][1]
            iface_index = msg['ifindex']
            host = {'ipaddr': ip_addr, 'mac_addr': mac_addr,
                    'ifindex': iface_index}
            self.notify(['remove_neigh', host])
            self.neighbours = list(filter(
                                   lambda x: x != host, self.neighbours))

    def notify(self, rheamsg):
        notification = pickle.dumps(rheamsg)
        if self.socket is not None:
            self.socket.send(notification)
            recv = self.socket.recv(8192)

    def ifaceTable(self, ipdb):
        ifaces = ipdb.by_name.keys()
        table = []
        for iface in ifaces:
            mac_addr = ipdb.interfaces[iface]['address']
            ip_addresses = ipdb.interfaces[iface]['ipaddr']
            ifindex = ipdb.interfaces[iface]['index']
            state = ipdb.interfaces[iface]['operstate']
            table.append({'ifname': iface, 'mac-address': mac_addr,
                          'IP-Addresses': [x for x in ip_addresses],
                          'ifindex': ifindex,
                          'state': state})
        return table

    def neighbourtable(self):
        return self.neighbours

    def returnunresolvedhost(self):
        return self.unresolvedneighbours

    def process_requests(self, ipdb, request):
        if request[0] == 'ifaceTable':
            res = self.ifaceTable(ipdb)
            result = ['ifaceTable', res]
            return pickle.dumps(result)

        if request[0] == 'neighbourtable':
            res = self.neighbourtable()
            result = ['neighbourtable', res]
            return pickle.dumps(result)

        if request[0] == 'get_unresolved':
            res = self.returnunresolvedhost()
            result = ['unresolved', res]
            return pickle.dumps(result)

    def handle_request(self, sock):
        is_active = True
        while is_active:
            received = sock.recv(8192)
            if len(received) != 0:
                request = pickle.loads(received)
                response = self.process_requests(self.ip, request)
                sock.send(response)

            if len(received) == 0:
                is_active = False
                sock.close()
        sock.close()

    def try_connect(self):
        while self.not_connect:
            try:
                self.socket = eventlet.connect(('127.0.0.1', 55651))
            except socket.error as e:
                pass
            else:
                self.not_connect = False

    def serve_forever(self):
        while self.serve:
            nl_sock, address = self.server.accept()
            self.pool.spawn_n(self.handle_request, nl_sock)
            log.info("Rhea has contacted us")
            self.try_connect()

if __name__ == "__main__":
    nlclient = NetlinkClient()
    nlclient.serve_forever()

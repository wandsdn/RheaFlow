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
from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from jsonHandler import JsonHandler
from RheaFlowEvents import EventRouterConnect, EventRouterDisconnect
from RheaFlowEvents import EventRouteReceived, EventRouteDeleted
from log import log


class RheaRouteReceiver(app_manager.RyuApp):

    _EVENTS = [EventRouterConnect, EventRouterDisconnect, EventRouteReceived,
               EventRouteDeleted]

    def __init__(self):
        super(RheaRouteReceiver, self).__init__()
        self.name = 'RheaRouteReceiver'
        self.jsonprocessor = JsonHandler()
        self.server_host = os.environ.get('RHEA_ROUTE_RECEIVER', '0.0.0.0')
        self.server_port = int(os.environ.get('RHEA_ROUTE_RECEIVER_PORT',
                               55650))
        self._stop = False

    def start(self):
        super(RheaRouteReceiver, self).start()
        self.logger.debug("listening on %s:%s", self.server_host,
                          self.server_port)

        return hub.spawn(StreamServer((self.server_host, self.server_port),
                                      self.loop).serve_forever)

    def loop(self, sock, addr):
        log.error("A router is connected, ip=%s, port=%s", addr[0],
                  addr[1])
        self.send_event_to_observers(EventRouterConnect(addr))
        if self._stop is False:
            is_active = True
        else:
            is_active = False

        while is_active:
            received = sock.recv(256)
            if len(received) == 0:
                is_active = False
                break
            msg = self.jsonprocessor.strip_message(received)
            check = self.jsonprocessor.verify_json(msg)

            if check is True:
                action, route = self.jsonprocessor.determine_action(msg)
                key_check, value_check = self.jsonprocessor.check_routeinfo(
                                                            route)
                if action == "added":
                    if key_check is True and value_check is True:
                        route_list = self.jsonprocessor.hand_over_route(route)
                        self.send_event_to_observers(EventRouteReceived(
                                                     route_list))
                        try:
                            lens = sock.send('Route processed and flows added')
                        except socket.error as e:
                            log.error("Error number is %d", e.errno)
                            break

                    else:
                        try:
                            sock.send('Route information not complete')
                            log.warning("Incomplete route information received, Route not processed")
                        except socket.error as e:
                            log.error("Error number is %d", e.errno)
                            break
                elif action == "removed":
                    if key_check is True and value_check is True:
                        route_list = self.jsonprocessor.hand_over_route(route)
                        self.send_event_to_observers(EventRouteDeleted(
                                                     route_list))
                        try:
                            lens = sock.send('Route removed and flows removed')
                        except socket.error as e:
                            log.error("Error number is %d", e.errno)
                            break
                    else:
                        try:
                            sock.send('Route information not complete')
                            log.warning("Incomplete route information received, Route not processed")
                        except socket.error as e:
                            log.error("Error number is %d", e.errno)
                            break
                else:
                    try:
                        sock.send('Unknown action')
                        log.warning("Recieved unknown action from router not processing route")
                    except socket.error as e:
                        log.error("Error number is %d", e.errno)
                        break
            else:
                fixed_route = self.jsonprocessor.fix_route(msg)
                log.debug('FIXED_ROUTE is %s', fixed_route)
                if fixed_route is None:
                    try:
                        sock.send("Error, Can not parse route")
                        log.error('Error, unknown object "%s" received',
                                  fixed_route)
                    except socket.error as e:
                        log.error("Error number is %d", e.errno)
                        break
                else:
                    check = self.jsonprocessor.verify_json(fixed_route)
                    if check is True:
                        action, route = self.jsonprocessor.determine_action(
                                        fixed_route)
                        key_check, value_check = (
                            self.jsonprocessor.check_routeinfo(route))
                        if action == "added":
                            if key_check is True and value_check is True:
                                route_list = (
                                    self.jsonprocessor.hand_over_route(route))
                                self.send_event_to_observers(
                                        EventRouteReceived(route_list))
                                try:
                                    sock.send("Route received and parsed")
                                except socket.error as e:
                                    log.error("Error number is %d", e.errno)
                                    break
                            else:
                                try:
                                    sock.send("Route information not complete")
                                    log.warning("Incomplete route information received, Route not processed")
                                except socket.error as e:
                                    log.error("Error number is %d", e.errno)
                                    break
                        elif action == "removed":
                            if key_check is True and value_check is True:
                                route_list = (
                                    self.jsonprocessor.hand_over_route(route))
                                self.send_event_to_observers(EventRouteDeleted
                                                             (route_list))
                                try:
                                    sock.send("Route removed and flows removed")
                                except socket.error as e:
                                    log.error("Error number is %d", e.errno)
                                    break
                            else:
                                try:
                                    sock.send("Route information not complete")
                                    log.warning("Incomplete route information recieved, Route not processed")
                                except socket.error as e:
                                    log.error("Error number is %d", e.errno)
                                    break
                        else:
                            try:
                                sock.send('Unknown action')
                                log.warning("Recieved unknown action from router,not processing route")
                            except socket.error as e:
                                log.error("Error number is %d", e.errno)
                                break
                    else:
                        try:
                            sock.send("Error !!! Unknown object received, cannot parse object")
                            log.error('Error, unknown object "%s" received',
                                      fixed_route)
                        except socket.error as e:
                            log.error("Error number is %d", e.errno)
                            break

        sock.shutdown(socket.SHUT_RDWR)
        self.send_event_to_observers(EventRouterDisconnect(addr))
        log.error("Router disconnected, ip=%s, port=%s", addr[0], addr[1])

    def shutdown(self):
        self._stop = True
        self.stop

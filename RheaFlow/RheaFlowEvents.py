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


from ryu.controller import event


class EventRouteReceiverBase(event.EventBase):
    def __init__(self, routerid):
        super(EventRouteReceiverBase, self).__init__()
        self.routerid = routerid

    def __str__(self):
        return '%s<ip=%s, port=%s>' % \
           (self.__class__.__name__,
            self.routerid[0], self.routerid[1])


class EventRouterConnect(EventRouteReceiverBase):
    def __init__(self, routerid):
        super(EventRouterConnect, self).__init__(routerid)


class EventRouterDisconnect(EventRouteReceiverBase):
    def __init__(self, routerid):
        super(EventRouterDisconnect, self).__init__(routerid)


class EventRouteReceived(event.EventBase):
    def __init__(self, route):
        super(EventRouteReceived, self).__init__()
        self.route = route

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.route)


class EventRouteDeleted(event.EventBase):
    def __init__(self, route):
        super(EventRouteDeleted, self).__init__()
        self.route = route

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.route)


class EventNeighbourNotify(event.EventBase):
    def __init__(self, neighbour, action):
        super(EventNeighbourNotify, self).__init__()
        self.neighbour = neighbour
        self.action = action


class EventSignalInterrupt(event.EventBase):
    def __init__(self, Interrupt_signal):
        super(EventSignalInterrupt, self).__init__()
        self.interrupt = Interrupt_signal

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.interrupt)


_RF_MSG_EVENTS = {}


def _rf_msg_name_to_ev_name(msg_name):
    return 'Event' + msg_name


def rf_msg_to_ev(msg):
    return rf_msg_to_ev_cls(msg.__class__)(msg)


def rf_msg_to_ev_cls(msg_cls):
    name = _rf_msg_name_to_ev_name(msg_cls.__name__)
    return _RF_MSG_EVENTS[name]


def _create_rf_msg_ev_class(msg_cls):
    name = _rf_msg_name_to_ev_name(msg_cls.__name__)

    if name in _RF_MSG_EVENTS:
        return

    cls = type(name, (EventRFMsgBase,),
               dict(__init__=lambda self, msg:
                    super(self.__class__, self).__init__(msg)))
    globals()[name] = cls
    _RF_MSG_EVENTS[name] = cls

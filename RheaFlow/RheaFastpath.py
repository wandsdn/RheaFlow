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
# Name: RheaFastPath.py
# Author : Oladimeji Fayomi
# Created : 16 March 2016
# Last Modified :
# Version : 1.0
# Description: Generates labels for FastPath and inter-switch links. it also
#              performs push or pop VLAN actions.

from ryu.ofproto import ofproto_v1_3 as ofproto, ether

class MetaLabel:
    """ An abstract class to label  packets with additional meta information

    See MetaVLAN for an implementation
    Adds the port as meta data to an OpenFlow action and assigns labels etc.

    Functions included are
    push_action_meta: Creates/appends to an OF action list for a datapath, the
                     addition of a meta label

    pop_action_meta: Creates/appends to an OF action list for a datapath, the
                     removal of a meta label
    match_meta: Creates/appends to an OF match list  for a datapath that
                matches the meta label

    allocate_label: Allocates a new label

    bad_label: A non existent label and unassigned

    This is based on the rffastpath.py added to the Vandervecken branch of
    RouteFlow by Richard Sanger.
    """

    def push_action_meta(self, label, parser, action=None):
        raise NotImplementedError("Should have implemented this")

    def pop_action_meta(self, parser, action=None):
        raise NotImplementedError("Should have implemented this")

    def match_meta(self,  parser, match=None):
        raise NotImplementedError("Should have implemented this")

    def allocate_label(self):
        raise NotImplementedError("Should have implemented this")

    def bad_label(self):
        return None


class MetaVLAN(MetaLabel):

    label = 2

    def push_action_meta(self, label, parser, action=None):
        if action is None:
            action = []
        action += [parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                   parser.OFPActionSetField(vlan_vid=(label | ofproto.OFPVID_PRESENT)),
                   parser.OFPActionSetField(vlan_pcp=0)]
        return action

    def pop_action_meta(self, parser, action=None):
        if action is None:
            action = []
        action.append(parser.OFPActionPopVlan())
        return action

    def match_meta(self, parser, label, match=None):
        if match is None:
            match = {}
        match['vlan_vid'] = label | ofproto.OFPVID_PRESENT
        return match

    def allocate_label(self):
        ret = self.label
        self.label += 1
        if ret >= (1 << 11):
            raise OverflowError("We've run out of VLAN labels for ports")
        return ret


if __name__ == "__main__":

    labeller = MetaVLAN()
    fp_label = labeller.allocate_label()

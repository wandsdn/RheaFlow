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
# Name: jsonHandler.py
# Author : Oladimeji Fayomi
# Created : 16 September 2015
# Last Modified :
# Version : 1.0
# Description: A class to process route information encoded in JSON
#              received from an IP routing daemon. The format of the
#              route information is:
#              { "Network": "192.168.1.0", "Netmask": "255.255.255.0",
#               "Next-hop": "192.12.10.1"}

import json
import string
import re


class JsonHandler(object):

    def __init__(self):
        return

    def strip_message(self, routermsg):
        ''' Remove  <SDN_ANNOUNCE> delimiters from message received
            from the router.
        '''
        msg = re.sub(r'<.+?>', '', routermsg)
        return msg

    def verify_json(self, msg):
        ''' Verify that the message is encoded in JSON '''
        try:
            route_msg = json.loads(msg)
        except ValueError as e:
            return False
        return True

    def determine_action(self, routermsg):
        ''' Determine that the message type.
            'added' - for new routes
            'removed' - for withdrawn routes
        '''
        msg = json.loads(routermsg)
        for action, route_info in msg.items():
            if action == "added":
                route = route_info[0]
                return action, route
            elif action == "removed":
                route = route_info[0]
                return action, route
            else:
                return None, None

    def check_routeinfo(self, route):
        ''' Verify that the message has the information needed for it to be
            processed like Network address, netmask and next-hop address.
        '''
        key_present = False
        value_present = False
        true_values = 0

        if 'prefix' in route and 'mask' in route and 'via' in route:
            key_present = True

        for info, value in route.items():
            # value =  jsonroute[info]
            if type(value) is str:
                if len(value) != 0:
                    true_values += 1
                else:
                    pass
            elif type(value) is list:
                if len(value) != 0:
                    true_values += 1
                else:
                    pass
            elif type(value) is dict:
                if len(value) != 0:
                    true_values += 1
                else:
                    pass
            elif type(value) is int and info == 'mask':
                if value >= 0 and value < 128:
                    true_values += 1
                else:
                    pass
            elif type(value) is int and not info == 'mask':
                if value >= 0:
                    true_values += 1
                else:
                    pass
            else:
                length = len(str(value))
                if length != 0:
                    true_values += 1
                else:
                    pass

        length = len(route)
        if length == true_values:
            value_present = True

        return key_present, value_present

    def fix_route(self, msg):
        ''' Fix received messages that are not properly encoded. '''

        if type(msg) is str:
            info = repr(msg)
            str_len = len(info)
            curly_close_list = []
            curly_start = string.find(info, "{")
            for char in range(0, str_len):
                if info[char] == '}':
                    curly_close_list.append(char)

            if not curly_close_list:
                if curly_start != -1:
                    info = info + "}"
                    curly_end = len(info) + 1
                    routefix_json = info[curly_start:curly_end]
                else:
                    routefix_json = None
            else:
                curly_end = max(curly_close_list) + 1
                routefix_json = info[curly_start:curly_end]

        elif type(msg) is dict:
            routefix_json = json.dumps(msg)

        elif type(msg) is list:
            routefix_json = json.dumps(msg)

        else:
            routefix_json = None

        return routefix_json

    def hand_over_route(self, route):
        list_info = []
        for info, value in route.items():
            list_info.append(value)

        return list_info

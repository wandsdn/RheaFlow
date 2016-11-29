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
# Name: RheaYaml.py
# Author : Dimeji Fayomi
# Created : 04 December 2015
# Last Modified :
# Version : 1.0
# Description:  This would open the YAML config passed to it
#               from the main RheaFlow controller application.
#               The YAML config file contains all the details
#               needed to successfully RheaFlow

from yaml import load_all
from log import log
import sys
import os


class RheaYAML(object):

    def __init__(self, filename=None):
        if filename:
            self.filestream = self.openfile(filename)
            if self.filestream:
                self.configs = self.loadconfig(self.filestream)
            else:
                self.configs = None

            self.closefile()
        else:
            self.configs = None

    def openfile(self, filename):
        if os.path.exists(filename) is True:
            try:
                stream = open(filename, 'r')
                log.info('Opened RheaFlow config file:%s', filename)
            except IOError as e:
                raise Exception("Could not open %s", filename)
                sys.exit(e.errno)
        else:
            log.error('Could not find %s', filename)
            sys.exit(1)
        return stream

    def loadconfig(self, filestream):
        all_configs = []
        try:
            datayaml = load_all(filestream.read())
        except ValueError as e:
            log.error("Error loading YAML config from file: %s", e.errno)
            sys.exit(e.errno)
        for data in datayaml:
            all_configs.append(data)

        if len(all_configs) == 1:
            return all_configs[0]
        else:
            return all_configs

    def get_dp_entry(self, configs, dp_id):
        '''
            Finds and returns the entry for a datapath from the
            loaded config using the datapath id.
        '''
        for identifier, values in configs.items():
            if identifier == 'datapaths':
                for dp in values:
                    try:
                        dpid_in_config = dp['dp_id']
                        if dpid_in_config == dp_id:
                            return dp
                    except KeyError:
                        log.error("DPID not found for a datapath in the\
                                  config")
        return None

    def fetch_OFPorts(self, switch):
        '''
            Fetch and return the openflow port numbers to be mapped
            on the datapath.
        '''
        try:
            DPOFPorts = switch['ports']
            return DPOFPorts
        except KeyError:
            log.error("No OF ports to be mapped for %s switch", switch['name'])
            return None

    def fetch_fpport(self, switch):
        try:
            dpfpport = switch['fastpath_port']
            return dpfpport
        except KeyError:
            log.error("No fastpath port found for %s switch", switch['name'])
            return None

    def fetch_vsfpport(self, switch):
        try:
            DPVSFPort = switch['fastpath_vs']
            return DPVSFPort
        except KeyError:
            log.error("No virtual switch fastpath port found for %s switch",
                      switch['name'])
            return None

    def vs_fp_entry(self):
        '''
            Get the fastpath interface to be used for the virtual
            switch.
        '''
        vs_fp_details = self.configs['Virtual-switch']
        try:
            vs_fastpath_int = vs_fp_details['fastpath_interface']
        except KeyError:
            log.warn("No fastpath interface specified on dp0")
            vs_fastpath_int = None
        try:
            vs_fastpath_port = vs_fp_details['fastpath_port']
        except KeyError:
            log.warn("No fastpath port specified on dp0")
            vs_fastpath_port = None
        return vs_fastpath_int, vs_fastpath_port

    def fetch_fastpath_entries(self):
        '''
            Return a list containing tuples of fastpath entries
            in the config.
        '''
        fastpath_entries = []
        for identifier, values in self.configs.items():
            if identifier == 'datapaths':
                for dp in values:
                    try:
                        dpid = dp['dp_id']
                    except KeyError:
                        log.error("No datapath ID included for a switch in the config")
                    try:
                        fp_on_dp = dp['fastpath_port']
                        fp_on_vs = dp['fastpath_vs']
                        if (fp_on_dp is not None) and (fp_on_vs is not None):
                            fastpath_entries.append((dpid, fp_on_dp, fp_on_vs))
                    except KeyError:
                        log.warn("No fastpath entries included in config for (dpid=%s)", dpid)

        return fastpath_entries

    def fetch_interswitch_links(self, switch):
        '''
            Return inter switch link configurations for a datapath
        '''
        try:
            interswitch_links = switch['interswitch_links']
        except KeyError:
            interswitch_links = None
        return interswitch_links

    def get_vs_port_prefix(self, configs, dpid):
        for identifier, values in configs.items():
            if identifier == 'datapaths':
                for dp in values:
                    try:
                        dpid_in_config = dp['dp_id']
                        if dpid_in_config == dpid:
                            vs_port_prefix_ = dp['vs_port_prefix']
                            return vs_port_prefix_
                    except KeyError:
                        log.error("DPID not found for datapath in the config")
        return None

    def dec_ttl_set(self, configs, dpid):
        for identifier, values in configs.items():
            if identifier == 'datapaths':
                for dp in values:
                    try:
                        dpid_in_config = dp['dp_id']
                        if dpid_in_config == dpid:
                            try:
                                decrement_ttl = dp['decrement_ttl']
                            except KeyError:
                                decrement_ttl = False
                                return decrement_ttl
                            return decrement_ttl
                    except KeyError:
                        log.error("DPID not found for datapath in the config")
        return None

    def closefile(self):
        self.filestream.close()


if __name__ == "__main__":

    yamlfile = 'mappingconfig.yaml'
    configclass = RheaYAML(yamlfile)
    log.warn("config/Data is: %s", configclass.configs)
    my_id = '0000000000000099'
    switch1 = configclass.get_dp_entry(configclass.configs, my_id)
    fp_entries = configclass.fetch_fastpath_entries()
    dp_ports = configclass.fetch_OFPorts(switch1)
    interswitch_links = configclass.fetch_interswitch_links(switch1)
    log.warn("Switch  1 :%s", switch1)
    log.warn("Our FP entries : %s", fp_entries)
    log.warn("Ports on switch1 : %s", dp_ports)
    configclass.closefile()

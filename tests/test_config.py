#!/usr/bin/env python
#-*- coding:utf-8 -*-


import hashlib
import logging
import sys
import os
import time
testdir = os.path.dirname(__file__)
configfile = '../etc/ryu/config.yaml'
srcdir = '../RheaFlow'
sys.path.insert(0, os.path.abspath(os.path.join(testdir, srcdir)))

import unittest
from RheaYAML import RheaYAML


class ConfigTestCase(unittest.TestCase):
    def setUp(self):
        logname = 'test_config'

        logger = logging.getLogger('%s.config' % logname)
        logger_handler = logging.StreamHandler(stream=sys.stderr)
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        logger_handler.setFormatter(
            logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
        logger.addHandler(logger_handler)
        logger.propagate = 0
        self.test_dp_ids = ['0000000000000099', '0000000000000089',
                            '0000000000000088']
        logger.setLevel(logging.CRITICAL)

        self.RheaYAMLConf = RheaYAML(configfile)

    def test_loadconfig(self):
        self.assertIsNotNone(self.RheaYAMLConf.configs)
        self.assertIs(type(self.RheaYAMLConf.configs), dict)

    def test_get_dp_entry(self):
        for test_dp_id in self.test_dp_ids:
            self.assertIsNotNone(self.RheaYAMLConf.get_dp_entry(
                self.RheaYAMLConf.configs, test_dp_id))
            self.assertIs(type(self.RheaYAMLConf.get_dp_entry(
                self.RheaYAMLConf.configs, test_dp_id)), dict)

    def test_fetch_OFPorts(self):
        for test_dp_id in self.test_dp_ids:
            test_dp = self.RheaYAMLConf.get_dp_entry(self.RheaYAMLConf.configs,
                    test_dp_id)
            test_DPOFPorts = self.RheaYAMLConf.fetch_OFPorts(test_dp)
            if test_DPOFPorts:
                self.assertIsNotNone(test_DPOFPorts)
                self.assertIs(type(test_DPOFPorts), dict)
                for port, addresses in test_DPOFPorts.items():
                    self.assertIs(type(addresses), list)
                    for addr in addresses:
                        self.assertIs(type(addr), str)
                        
    def test_fetch_fpport(self):
        for test_dp_id in self.test_dp_ids:
            test_dp = self.RheaYAMLConf.get_dp_entry(self.RheaYAMLConf.configs,
                    test_dp_id)
            test_dpfpport = self.RheaYAMLConf.fetch_fpport(test_dp)
            if test_dpfpport:
                self.assertIs(type(test_dpfpport), int)


    def test_fetch_vsfpport(self):
        for test_dp_id in self.test_dp_ids:
            test_dp = self.RheaYAMLConf.get_dp_entry(self.RheaYAMLConf.configs,
                    test_dp_id)
            test_vsfpport = self.RheaYAMLConf.fetch_vsfpport(test_dp)
            if test_vsfpport:
                self.assertIs(type(test_vsfpport), int)

    def test_vs_fp_entry(self):
        test_vs_fastpath_int, test_vs_fastpath_port = self.RheaYAMLConf.vs_fp_entry()
        if test_vs_fastpath_int:
            self.assertIs(type(test_vs_fastpath_int), str)
        if test_vs_fastpath_port:
            self.assertIs(type(test_vs_fastpath_port), int)

    def test_fetch_fastpath_entries(self):
        test_fastpath_entries = self.RheaYAMLConf.fetch_fastpath_entries()
        if test_fastpath_entries:
            self.assertIs(type(test_fastpath_entries), list)
            for entry in test_fastpath_entries:
                self.assertIs(type(entry), tuple)
                (dpid, fp_on_dp, fp_on_vs) = entry
                self.assertIs(type(dpid), str)
                self.assertIs(type(fp_on_dp), int)
                self.assertIs(type(fp_on_vs), int)

    def test_fetch_interswitch_links(self):
        for test_dp_id in self.test_dp_ids:
            test_dp = self.RheaYAMLConf.get_dp_entry(self.RheaYAMLConf.configs,
                    test_dp_id)
            test_isl = self.RheaYAMLConf.fetch_interswitch_links(test_dp)
            if test_isl:
                self.assertIs(type(test_isl), dict)
                for local_port, remote_end in test_isl.items():
                    self.assertIs(type(local_port), int)
                    self.assertIs(type(remote_end), dict)
                    for rem_dpid , rem_port in remote_end.items():
                        self.assertIs(type(rem_dpid), str)
                        self.assertIs(type(rem_port), int)

    def test_get_vs_port_prefix(self):
        for test_dp_id in self.test_dp_ids:
            test_vs_port_prefix = self.RheaYAMLConf.get_vs_port_prefix(self.RheaYAMLConf.configs,
                    test_dp_id)
            if test_vs_port_prefix: 
                self.assertIs(type(test_vs_port_prefix), str)

    def test_dec_ttl_set(self):
        for test_dp_id in self.test_dp_ids:
            test_dec_ttl = self.RheaYAMLConf.dec_ttl_set(self.RheaYAMLConf.configs,
                    test_dp_id)
            if test_dp_id == '0000000000000099':
                self.assertFalse(test_dec_ttl)
            elif test_dp_id == '0000000000000089':
                self.assertTrue(test_dec_ttl)
            elif test_dp_id == '0000000000000088':
                self.assertFalse(test_dec_ttl)
            else:
                return

if __name__ == "__main__":
    unittest.main()

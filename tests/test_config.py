#!/usr/bin/env python
#-*- coding:utf-8 -*-


import hashlib
import logging
import sys
import os

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
            if self.assertIsNotNone(test_DPOFPorts):
                self.assertIs(type(test_DPOFPorts), dict)
                for port, addresses in test_DPOFPorts.items():
                    self.assertIs(type(addresses), list)
                    for addr in addresses:
                        self.assertIs(type(addr), string)

if __name__ == "__main__":
    unittest.main()

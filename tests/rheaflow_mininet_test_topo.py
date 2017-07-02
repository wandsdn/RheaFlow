"""Topology components for RheaFlow Mininet unit tests."""

import os
import socket
import string

import netifaces

from mininet.topo import Topo
from mininet.node import Controller
from mininet.node import Host
from mininet.node import OVSSwitch

class RheaFlowSwitch(OVSSwitch):
    """Switch that will be used by all tests."""

    def __init__(self, name, **params):
        OVSSwitch.__init__(
            self, name=name, datapath='kernel', **params)

class TestHost(Host):
    """Implementation of a Mininet host."""

    def config(self, **params):
        """Configure TestHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""
        super_config = super(TestHost, self).config(**params)
        intf = self.defaultIntf()
        for cmd in (
                'ip -4 addr flush dev %s' % intf,
                'ip -6 addr flush dev %s' % intf,
                'ip -4 addr add %s dev %s' % (params['ipv4'], intf)
                'ip -6 addr add %s dev %s' % (params['ipv6'], intf)):
            self.cmd(cmd)
        return super_config

class RheaFlowSwitchTopo(Topo):
    """RheaFlow switch topology that contains a software switch."""

    def _get_sid_prefix(self, ports_served):
        """Return a unique switch/host prefix for a test."""
        id_chars = string.letters + string.digits
        id_a = int(ports_served / len(id_chars))
        id_b = ports_served - (id_a * len(id_chars))
        return '%s%s' % (
            id_chars[id_a], id_chars[id_b])

    def _add_test_host(self, sid_prefix, host_n):
        """Add a single test host."""
        host_name = 't%s%1.1u' % (sid_prefix, host_n + 1)
        # May need to pass ipv4 and ipv6 params to addHost
        return self.addHost(
            name = host_name,
            cls = TestHost)

    def _add_rheaflow_switch(self, sid_prefix, port, dpid):
        """Add a RheaFlow switch."""
        switch_name = 's%s' % sid_prefix
        return self.addSwitch(
            name = switch_name,
            cls = RheaFlowSwitch,
            listenPort = port,
            dpid = rheaflow_mininet_test_util.mininet_dpid(dpid))

    def build(self, ports_sock, dpid=0, n=0):
        port, port_served = rheaflow_mininet_test_util.find_free_port(ports_sock)
        sid_prefix = self._get_sid_prefix(ports_served)
        for host_n in range(n):
            self._add_test_host(sid_prefix, host_n)
        switch = self._add_rheaflow_switch(sid_prefix, port, dpid)
        for host in self.hosts():
            self.addLink(host, switch)

class RheaFlowHwSwitchTopo(RheaFlowSwitchTopo):
    """RheaFlow switch topology that contains a hardware switch."""

    def build(self, ports_sock, dpid=0, n=0):
        port, port_server = rheaflow_mininet_test_util.find_free_port(ports_sock)
        sid_prefix = self._get_sid_prefix(ports_served)
        for host_n in range(n):
            self._add_test_host(sid_prefix, host_n)
        print('bridging hardware switch DPID %s (%x) dataplane via OVS DPID %s (%x)' % (
           dpid, int(dpid), remap_dpid, int(remap_dpid)))
        dpid = remap_dpid
        switch = self._add_faucet_switch(sid_prefix, port, dpid)
        for host in self.hosts():
            self.addLink(host, switch)

class BaseRheaFlow(Controller):

    controller_intf = None
    tmpdir = None
    BASE_CARGS = ' '.join((
        '--verbose',
        '--use-stderr',
        '--ofp-tcp-listen-ports=%s'))

    def __init__(self, name, tmpdir, controller_intf=None, cargs='', **kwargs):
        name = '%s-%u' % (name, os.getpid())
        self.tmpdir = tmpdir
        self.controller_intf = controller_intf
        super(BaseRheaFlow, self).__init__(
            name, cargs=self._add_cargs(cargs), **kwargs)

    def __add_cargs(self, cargs):
        ipv4_host = ''
        if self.controller_intf is not None:
            # pylink: disable=no-member
            ipv4_host = '--ofp-listen-host=%s' % netifaces.ifaddresses(
                 self.controller_intf)[socket.AF_INET][0]['addr']
        return ' '.join((self.BASE_CARGS, ipv4_host, cargs))

    def _start_tcpdump(self):
        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s' % self.controller_intf,
            '-w %s/%s-of.cap' % (self.tmpdir, self.name),
            'tcp and port %u' % self.port,
            '>/dev/null',
            '2>/dev/null',
        ))
        self.cmd('tcpdump %s &' % tcpdump_args)

    def _tls_cargs(self, ofctl_port, ctl_privkey, ctl_cert, ca_certs):
        tls_cargs = []
        for carg_val, carg_key in ((ctl_privkey, 'ctl_privkey'),
                                   (ctl_cert, 'ctl_cert'),
                                   (ca_certs, 'ca-ca_certs')):
            if carg_val:
                tls_cargs.append(('--%s=%s' % (carg_key, carg_val)))
        if tls_cargs:
            tls_cargs.append(('--ofp-ssl-listen-port=%u' % ofctl_port))
        return ' '.join(tls_cargs)

    def _command(self, args):
        return 'PYTHONPATH=../ ryu-manager %s' % args

    def start(self):
        self._start_tcpdump()
        super(BaseRheaFlow, self).start()

class RheaFlow(BaseRheaFlow):
    """Start a RheaFlow controller."""

    def __init__(self, name, tmpdir, controller_intf,
                 ctl_privkey, ctl_cert, ca_certs,
                 ports_sock, port, **kwargs):
        self.ofctl_port, _ = rheaflow_mininet_test_util.find_free_port(
            ports_sock)
        cargs = ' '.join((
            '--wsapi-host=127.0.0.1',
            '--wsapi-port=%u' % self.ofctl_port,
            self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs)))
        super(RheaFlow, self).__init__(
            name,
            tmpdir,
            controller_intf,
            cargs=cargs,
            cdir=rheaflow_mininet_test_util.RHEAFLOW_DIR,
            command=self._command('ryu.app.ofctl_rest RheaFlow.RheaFlow'),
            port=port,
            **kwargs)

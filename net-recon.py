#!/usr/bin/python2
#
##################################################################################
#
# 888b    888          888         8888888b.
# 8888b   888          888         888   Y88b
# 88888b  888          888         888    888
# 888Y88b 888  .d88b.  888888      888   d88P .d88b.   .d8888b .d88b.  88888b.
# 888 Y88b888 d8P  Y8b 888         8888888P" d8P  Y8b d88P"   d88""88b 888 "88b
# 888  Y88888 88888888 888  888888 888 T88b  88888888 888     888  888 888  888
# 888   Y8888 Y8b.     Y88b.       888  T88b Y8b.     Y88b.   Y88..88P 888  888
# 888    Y888  "Y8888   "Y888      888   T88b "Y8888   "Y8888P "Y88P"  888  888
#
# Net-Recon | A tool used for network and Active Directory information gathering
#             using passive network protocols
#
# Copyright (C) 2018 (k0fin)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##################################################################################

import sys
import os
import glob
import random

from modules.winbrowser import *
from modules.lldp import *
from modules.cdp import *
from modules.mdns import *
from modules.dhcp import *
from modules.nbns import *
from modules.console import *

from scapy.all import *
from scapy.utils import *

from argparse import ArgumentParser

class NetRecon:

    def __init__(self):

        pass

def banner():

    with open('{}/banners/default.banner'.format(os.getcwd()),'r') as bfile:
        print bfile.read().strip()

    print ''

def create_report(rname, rkeys, quiet=False):

    hostlist = []
    domlist = []

    hostjson = rkeys['hosts']
    domjson = rkeys['domains']

    hosts = sorted(list(set(hostjson.keys())))
    doms = sorted(list(set(domjson.keys())))

    print ''

    domcomstr = '''

    print '-' * 100
    print 'Domain Names'
    print '-' * 100

    for dom in doms:

        if not quiet:
            print dom.upper()

        domlist.append(dom)

        domdatajson = domjson[dom]
        dom_data_keys = domdatajson.keys()

        for dom_data_key in dom_data_keys:

            if not quiet:
                print '  - {} {}'.format(dom_data_key.upper(), domdatajson[dom_data_key])

        print ''

    print '-' * 100
'''

    print '=' * 100
    print 'Net-Recon Results'
    print '=' * 100

    print '-' * 100
    print 'Hosts'
    print '-' * 100
    for host in hosts:

        if not quiet:
            print 'Host: {}'.format(host.upper())

        hostlist.append(host)

        hostdatajson = hostjson[host]
        host_data_keys = sorted(list(set(hostdatajson.keys())))

        for host_data_key in host_data_keys:
            host_data_val = hostdatajson[host_data_key]
            host_data_val_type = str(type(host_data_val)).split()[1].rstrip('>').lstrip("'").rstrip("'")

            if host_data_val_type == 'list':
                host_data_val = ', '.join(host_data_val)

            if not quiet:
                print '  - {0:20} {1:10}'.format(host_data_key.upper(), host_data_val)

        print ''

    print ''

    print '-' * 100
    print 'Domains'
    print '-' * 100
    for dom in doms:
        if not quiet:
            print dom.upper()

        domlist.append(dom)

        domdatajson = domjson[dom]
        dom_data_keys = domdatajson.keys()

        for dom_data_key in dom_data_keys:

            if not quiet:
                print '  - {} {}'.format(dom_data_key.upper(), domdatajson[dom_data_key])

        print ''

#    print '[*] Done! Report written to outfile: {}'.format(rname)

def main():

    parser = ArgumentParser(description='A tool for parsing network/Active Directory information from packet captures')

    parser.add_argument('--pcap', help='Packet capture to read from')
    parser.add_argument('--session', default=False, help='Load a previously generated Net-Recon session file (filename.nrecon)')

    args = parser.parse_args()

    pcap = args.pcap
    session = args.session

    if pcap:
        loadfile = pcap
        check_sessions_path = sessions_path_exists()

        if not check_sessions_path:
            os.system('mkdir {}'.format('{}/sessions'.format(os.getcwd())))

        sessionfile = '{}net-recon-session-{}'.format('{}/sessions/'.format(os.getcwd()), loadfile.split('/').pop().rsplit('.pcap')[0].strip())

        recon_keys = {'hosts':{}, 'domains':{}, 'protocols':{}, 'routers':{}}

        print ColorOut('Loading network packets from PCAP file: {}...\n'.format(loadfile)).blue()

        pcap_buf = rdpcap(loadfile)

        print '  - Searching for NBT-NS information...'
        nbns_info = NBNS(pcap_buf, recon_keys).search()

        print '  - Searching for CDP information...'
        cdp_info = CDP(pcap_buf, recon_keys).search()

        print '  - Searching for LLDP information...'
        lldp_info = LLDP(pcap_buf, recon_keys).search()

        print '  - Searching for DHCP information...'
        dhcp_info = BootStrap(pcap_buf, recon_keys).search()

        print '  - Searching for MDNS information...'
        mdns_info = MDNS(pcap_buf, recon_keys).search()

        print '  - Searching for Windows Browser information...'
        win_browse_info = WinBrowser(pcap_buf, recon_keys).search()

        net_recon_shell(sessionfile, win_browse_info)

    if session:

        sessionfile = session
        load_file, load_keys = session_handler(sfile=sessionfile)

        net_recon_shell(load_file, load_keys)


if __name__ == '__main__':

    banner()
    main()

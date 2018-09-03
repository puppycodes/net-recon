#!/usr/bin/python2

import sys
import os
import glob
import random

from scapy.all import *
from scapy.utils import *

class BootStrap:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(IP) and packet.getlayer(BOOTP):
                    raw_packet = list(str(packet[BOOTP]))

                    if raw_packet[0] == '\x01':

                        if raw_packet[254:][0] == '\xc0':
                            hostname = ''.join(raw_packet[260:]).rsplit('Q')[0].strip()
                            fqdn = ''.join(raw_packet[270:]).replace('\x00', '^').split('^').pop().rsplit('<')[0].strip()

                        else:
                            hostname = ''.join(raw_packet[254:]).rsplit('<')[0].rsplit('Q')[0].strip()
                            fqdn = None

                        if hostname not in self.keys['hosts'].keys():
                            mac = packet[Ether].src
                            ipv4 = packet[IP].src
                            self.keys['hosts'].update({hostname:{'mac': mac, 'fqdn': fqdn, 'ipv4': ipv4, 'protocol': 'DHCPv4/BOOTP_REQ'}})

                        else:
                            self.keys['hosts'][hostname].update({hostname:{'fqdn': fqdn}})

                    else:

                        dhcp_id_list = []
                        router_list = []
                        dns_list = []
                        dns_addr_length = int(raw_packet[256].encode('hex'), 16)
                        dns_addr_count = dns_addr_length / 4

                        dhcp_srv_split = list(raw_packet[245:249])
                        router_split = list(raw_packet[251:255])
                        dns_split = list(raw_packet[257:(257 + dns_addr_length)])
                        dns_count = 0

                        for dhcp in dhcp_srv_split:
                            octet = int(dhcp.encode('hex'), 16)
                            dhcp_id_list.append(str(octet))

                        for router in router_split:
                            octet = int(router.encode('hex'), 16)
                            router_list.append(str(octet))

                        for dns in dns_split:
                            octet = int(dns.encode('hex'), 16)
                            dns_list.append(str(octet))
                            dns_count += 1

                            if dns_count == (dns_addr_length / dns_addr_count):
                                dns_list.append(',')

                        dhcp_srv_id = '.'.join(dhcp_id_list)
                        router_addr = '.'.join(router_list)
                        dns_addr_chars = '.'.join(dns_list).lstrip('.').rstrip('.')
                        dns_addrs = sorted(list(set(dns_addr_chars.split('.,.'))))

                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        hostname = 'RTR{}'.format(mac.replace(':',''))

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'mac': mac, 'router': router_addr, 'dhcp': dhcp_srv_id, 'dns': dns_addrs, 'ipv4': ipv4, 'protocol': 'DHCPv4/BOOTP_ACK'}})

                        else:
                            if 'router' not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'router': router_addr})

                            if 'dhcp' not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'router': router_addr})
                                self.keys['hosts'][hostname].update({'router': router_addr})



        return self.keys


#!/usr/bin/python2

import sys
import os
import glob
import random

from scapy.all import *
from scapy.utils import *

class WinBrowser:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(UDP) and packet[UDP].sport == 138 and packet[UDP].dport == 138:
                    raw_packet = list(str(packet[Raw]))
                    browser_cmd = raw_packet[85:87]

                    if browser_cmd[1] == '\x01':

                        announcement = 'Host Announcement (0x01)'
                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        hostname = ''.join(raw_packet[92:]).rsplit('\x00')[0].strip()

                        if list(raw_packet[108:110])[0] == '\x06' and list(raw_packet[108:110])[1] == '\x01':
                            os = 'Windows 7 / Windows Server 2008 R2 (Windows 6.1)'

                        else:
                            os = None

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'announcement': announcement, 'mac': mac, 'ipv4': ipv4, 'os': os, 'protocol': 'Windows Browser Protocol'}})

                        else:

                            if 'os' not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'os':os})

                    elif browser_cmd[1] == '\x0c':

                        announcement = 'Domain/Workgroup Announcement (0x0c)'
                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        domain = ''.join(raw_packet[92:]).rsplit('\x00')[0].strip()
                        win_major = int(raw_packet[108].encode('hex'), 16)
                        win_minor = int(raw_packet[109].encode('hex'), 16)

                        windows_major_minor = '{}.{}'.format(win_major, win_minor)
#                        print windows_major_minor
#                        sys.exit()
                        hostname = ''.join(raw_packet[118:]).rstrip('\x00')

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'announcement': announcement, 'mac': mac, 'ipv4': ipv4, 'domain': domain, 'protocol': 'Windows Browser Protocol', 'windows_version': windows_major_minor}})

                        else:
                            if 'domain' not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'domain': domain})

                        if domain not in self.keys['domains'].keys():
                            self.keys['domains'].update({domain:{'protocol': 'Windows Browser Protocol'}})


                    elif browser_cmd[1] == '\x0f':

                        announcement = 'Local Master Announcement (0x0f)'
                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        hostname = ''.join(raw_packet[92:]).rsplit('\x00')[0].strip()
                        comment = None
                        if raw_packet[118:] != ['\x00']:
                            comment = ''.join(raw_packet[118:]).strip()

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'announcement': announcement, 'mac': mac, 'ipv4': ipv4, 'comment': comment, 'protocol': 'Windows Browser Protocol'}})

                        else:
                            if comment not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'comment': comment})

        return self.keys

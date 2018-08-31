#!/usr/bin/python2

import sys
import os
import glob
import random
import struct

from scapy.all import *
from scapy.utils import *

def decode_nbns_name(nbn):
    """Return the NetBIOS first-level decoded nbname."""
    if len(nbn) != 32:
        return nbn

    l = []

    for i in range(0, 32, 2):
        l.append(chr(((ord(nbn[i]) - 0x41) << 4) |
                     ((ord(nbn[i+1]) - 0x41) & 0xf)))

    return ''.join(l).split('\x00', 1)[0]

class NBNS:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()


        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(Ether) and packet.getlayer(UDP) and packet.getlayer(NBNSQueryRequest) and packet[UDP].dport == 137 and packet[Ether].dst == 'ff:ff:ff:ff:ff:ff':
                    raw_packet = list(str(packet[NBNSQueryRequest]))

                    mac = packet[Ether].src
                    ipv4 = packet[IP].src
                    hostname = 'NBNS-Source-{}'.format(ipv4)

                    transaction_id = list(raw_packet[0:2])
                    flags = list(raw_packet[2:4])
                    questions = list(raw_packet[4:6])
                    answers = list(raw_packet[6:8])
                    nbns_name = ''.join(raw_packet[13:len(raw_packet) - 5])
                    nbns_query_name = decode_nbns_name(nbns_name).split(' ')[0].strip()

#                    print 'TID'
#                    print transaction_id

#                    print 'Flags'
#                    print flags

#                    print 'Questions'
#                    print questions

#                    print 'Answers'
#                    print answers

                    if hostname != None and hostname not in self.keys['hosts'].keys():
                        self.keys['hosts'].update({hostname: {'protocol': 'NBNS', 'ipv4': ipv4, 'mac': mac, 'nbns_query_name': nbns_query_name}})

        return self.keys



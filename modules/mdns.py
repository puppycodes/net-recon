#!/usr/bin/python2

import sys
import os
import glob
import random

from scapy.all import *
from scapy.utils import *

class MDNS:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()


        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(UDP) and packet.getlayer(IP) and packet[UDP].sport == 5353 and packet[UDP].dport == 5353 and packet[IP].dst == '224.0.0.251':
                    raw_packet = str(packet[DNS]).replace('\r','\t').split('\t')
                    try:
                        domain = raw_packet[1].split()[0].replace('\x05','.').replace('\x04','.').split('\x00')[0].strip()

                    except IndexError:
                        domain = None

                    if domain != None and domain not in self.keys['domains'].keys():
                        self.keys['domains'].update({domain: {'protocol': 'mdns', 'client_ipv4': packet[IP].src}})

        return self.keys



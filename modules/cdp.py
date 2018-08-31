#!/usr/bin/python2

import sys
import os
import glob
import random

from scapy.all import *
from scapy.utils import *

class CDP:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(Dot3) and packet[Dot3].dst == '01:00:0c:cc:cc:cc':
                    raw_packet = list(str(packet[Raw]))

                    mac = packet[Dot3].src

                    cdp_version = str(int(raw_packet[0].encode('hex'), 16))
                    cdp_ttl = str(int(raw_packet[1].encode('hex'), 16))
                    cdp_checksum = str(''.join(raw_packet[2:4]).encode('hex'))
                    cdp_device_id_type = str(''.join(raw_packet[4:6]).encode('hex'))
                    cdp_device_id_length = str(int(''.join(raw_packet[6:8]).encode('hex'), 16))
                    hostname = str(''.join(raw_packet[8:(int(cdp_device_id_length) + 4)]))
                    cdp_addresses_length = raw_packet[(int(cdp_device_id_length) + 6):(int(cdp_device_id_length) + 8)]


                    print ''


                    if hostname not in self.keys['hosts'].keys():
                        self.keys['hosts'].update({hostname:{'mac': mac, 'cdp_device_id_type': cdp_device_id_type, 'cdp_version': cdp_version, 'cdp_ttl': cdp_ttl, 'cdp_checksum': cdp_checksum, 'protocol': 'CDP'}})

        return self.keys

#!/usr/bin/python2

import sys
import os
import glob
import random

from scapy.all import *
from scapy.utils import *

class LLDP:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(Ether) and packet[Ether].dst == "01:80:c2:00:00:0e":
                    # Get source MAC and build list of bytes from packet
                    mac = packet[Ether].src
                    raw_packet = list(str(packet[Raw]))

                    hostname = 'LLDP-Host-{}'.format(mac)
                    system_name = hostname
                    system_description = 'LLDP Advertiser'
                    mgt_ipv4 = 'Unknown'
                    mgt_802 = 'Unknown'
                    mgt_address_type = 'Unknown'
                    address = 'Unknown'

                    # Get Chassis ID
                    chassis_id = ''
                    chassis_id_bytes = list(str(packet))[17:23]

                    for chassis_obj in chassis_id_bytes:
                        chassis_byte = str(chassis_obj.encode('hex'))
                        chassis_id += '{}:'.format(str(chassis_obj.encode('hex')))

                    chassis_id_mac = chassis_id.rstrip(':')

                    # Get LLDP System Name
                    if '\x0a' in raw_packet:

                        system_name_start = raw_packet.index('\x0a')
                        system_name_list = raw_packet[(system_name_start + 2):]
                        system_name = ''.join(system_name_list).rsplit('\x0c')[0]

                        hostname = system_name

                    if '\x0c' in raw_packet:
                    # Get LLDP System Description

                        system_description_start = raw_packet.index('\x0c')
                        system_description_list = raw_packet[(system_description_start + 2):]
                        system_description = ''.join(system_description_list).rsplit('\x0e')[0].rsplit('\x08')[0]

                    if '\x0e' in raw_packet:
                    # Get LLDP Management Address

                        mgt_addr_type_index = raw_packet.index('\x10')
                        mgt_addr_type = raw_packet[(mgt_addr_type_index + 3)]

                        if mgt_addr_type == '\x06':
                            mgt_address_type = '802 Media'
                            mgt_addr_start = list(''.join(system_description_list).rsplit('\x0e')[-1:][0][2:8])
                            mgt_802_addr = ''

                            for mgt in mgt_addr_start:
                                mgt_obj = mgt.encode('hex')
                                mgt_802_addr += '{}.'.format(mgt_obj)

                            mgt_802 = mgt_802_addr.rstrip('.')

                        if mgt_addr_type == '\x01':
                            mgt_address_type = 'IPv4'
                            mgt_addr_start = raw_packet[(mgt_addr_type_index + 4):(mgt_addr_type_index + 8)]
                            mgt_addr_list = []
#                            mgt_addr_start = list(''.join(system_description_list).rsplit('\x0e')[1].split()[1][2:])[0:4]


                            for mgt in mgt_addr_start:
                                octet = int(mgt.encode('hex'), 16)
                                mgt_addr_list.append(str(octet))

                                mgt_ipv4 = '.'.join(mgt_addr_list)

                            # Parse LLDP Telecommunications data / TR-41 data (could also potentially be repeated system name)
                        if '\xfe' in raw_packet and mgt_addr_type == '\x01':

                            teledata_start = raw_packet.index('\xfe')
                            teledata_list = ''.join(raw_packet[teledata_start:]).lstrip('\xfe').split('\xfe')[1::]

                            if len(teledata_list) == 4:

                                media_capabilities = teledata_list[0]
                                network_policy = teledata_list[1]
                                location_identification = teledata_list[2]
                                extended_power = teledata_list[3]


                                country = location_identification[8:10]
                                state = location_identification[12:14]
                                city = ''.join(location_identification[16:]).rsplit('\x06')[0]
                                street = ''.join(location_identification[16:]).rsplit('\x06')[1].rsplit('\x13')[0].strip()
                                number = ''.join(location_identification[16:]).rsplit('\x06')[1].split('\x13')[1][1:5].strip()
                                unit = location_identification[-3:]

                                address = '{} {} {} - {}, {} - {}'.format(number, street, unit, city, state, country)


                    if hostname not in self.keys['hosts'].keys():
                        self.keys['hosts'].update({hostname:{'mac': mac, 'mgt_address_type': mgt_address_type, 'chassis_id': chassis_id_mac, 'fingerprints': system_description, 'management_ipv4': mgt_ipv4, 'system_name': system_name, 'tr-41-location-id': address, 'protocol': 'LLDP'}})

        return self.keys


    ==============================================================================
    
    888b    888          888         8888888b.                                    
    8888b   888          888         888   Y88b                                   
    8CDP8b  888          888         888    888                                   
    888Y88b 888  .d88b.  888888      888   d88P .d88b.   .d8888b .d88b.  8DHCPb.  
    888 Y88b888 d8P  Y8b 888         8888888P" d8P  Y8b d88P"   d88""88b 888 "88b 
    888  Y8WIN8 8BROWSER 888  8STFU8 888 T88b  888LLDP8 888     888  888 888  888 
    888   Y8888 Y8b.     Y88b.       888  T88b Y8b.     Y88b.   Y88..88P 888  888 
    888    Y888  "Y8888   "Y888      888   T88b "Y8888   "Y88888 "Y88P"  888  888
    
     [ Network segment reconnaissance using discovery and broadcast protocols ]
                                [ Written by k0fin ]

    ------------------------------------------------------------------------------
    ==============================================================================

# Net-Recon | Written by k0fin | Tested and Supported on Kali Linux

## About

* Net-Recon is a tool written to perform information gathering on internal networks.
* Since net-recon utilizes host-discovery and broadcast-related protocols, information which may be valuable to an attacker
  can be obtained without ever actively scanning or querying a host.

* This tool does not parse or search for network-based credentials.
* If you wish to parse a PCAP for secrets, be sure to check out the super awesome net-creds (https://github.com/DanMcInerney/net-creds)

## Supported Protocols and Data Types

* Link Local Discovery Protocol
  - Network switch system names
  - Network switch system fingerprints
  - Network switch management addresses
  - TR-41 Commitee Location Identification

* Microsoft Windows Browser Protocol (Host, Domain/Workgroup, and Local Master Browser Announcements)
  - Hostnames
  - Windows OS Version
  - Server Type
  - Host Comment (reveals potentially sensitive information / service fingerprints)

* DHCPv4 Bootstrap
  - DHCP Server IP Address
  - Router IP Address
  - Domain Name Server Addresses
  - Hostnames

* Cisco Discovery Protocol
  - CDP Checksum
  - CDP Device Name / ID
  - CDP Device ID Type
  - CDP Version

* MDNS
  - Internal domain names
  - Lookup types

* NetBIOS Name Service
  - NetBIOS names
  - Source MAC and IPv4 Addresses
  - NBNS Transaction ID's

## Protocols and Data Types Currently In Progress

* SMB Session Setup AndX Response
* Kerberos
* HTTP/WPAD

## Usage

* Perform a packet capture to a PCAP file using a tool like tcpdump.

    tcpdump -i <iface> -w <pcap_outfile_path>

* Then, use net-recon to analyze the PCAP file for info.

    ./net-recon.py --pcap <pcap_file_path>

## PCAP Files

* Included with net-recon are several sample PCAP files for related protocols from Wireshark.
  They can be found in the "pcaps" folder.

## Todo

* Add live interface packet capture support


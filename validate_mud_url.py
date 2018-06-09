#!/usr/bin/env python

""" validate_mud_url.py
Use this script to find MUD URLs in LLDP and DHCP packets found in a pcap file.
FUTURE: If a MUD URL is not found, check the other TLVs or options or TLVs 
        to see if there is a malformed MUD URL in recognizable way.
"""

from __future__ import print_function

import dpkt
import datetime
import socket
import validators
import argparse


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form 
           (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % dpkt.compat.compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def log_eth_packet(timestamp, eth):
    """ Print a record of an interesting Ethernet packet

       Args:
           timestamp: The timestamp from the PCAP record
           eth: The ethernet header
    """
    # Print out the timestamp in UTC
    print('\n\nTimestamp: {0}'\
                .format(str(datetime.datetime.utcfromtimestamp(timestamp))))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)


def log_dhcp_packet(timestamp, eth, msg_type):
    """Print a record of an intersting DHCP packet

       Args:
           timestamp: The timestamp from the PCAP record
           eth: The ethernet header
           msg_type: A string describing the type of DHCP message
    """
    log_eth_packet(timestamp, eth)

    # Print some IP & UDP data
    ip = eth.data
    udp = ip.data
    print('    IP: %s -> %s   (len=%d ttl=%d prot=%d)' % \
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, ip.p))
    print('    UDP: (sport=%d dport=%d ulen=%d sum=%d)' % \
            (udp.sport, udp.dport, udp.ulen, udp.sum))

    # Print the DHCP message type
    print('    DHCP: Message Type:', msg_type)


def validate_mud_url(url, source):
    """Validate that a MUD URL is properly formed according
       to the MUD specification. Note that this does not
       validate that the MUD file actually exists.

       Args:
           url: The MUD URL discovered in packet
           source: A string describing in which type of packet the
                   MUD URL was discovered

       Validation include:
        -- The URL begins with 'https://'
        -- The URL is properly formed, according to URL
           validation rules
    """
    errs = 0

    print('    MUD Option found in {0}: {1}'.format(source, url))
    #print(url.encode('ascii'))

    if not url.startswith ('https://'):
        print('        ERROR: MUD URL does not begin with https://')
        errs = errs + 1

    if url.endswith ('.json'):
        print('        ERROR: MUD URL should not end with .json.')
        print('               The MUD manager will add .json to the URL when')
        print('               it needs it.')
        errs = errs + 1

    if not validators.url(url):
        print('        ERROR: Not a well formed URL.')
        print('               Ensure the MUD URL matches the format of:')
        print('                   https://something.com/string/string/string.json')
        print('               where "something.com" should be a domain name')
        print('               and each "string" contains only legal characters')
        print('               for a URL')
        errs = errs + 1

    if (not errs):
        print('        OK!')

def find_mud_url(pcap):
    """Look for a MUD URLs in frames discovered in a pcap. If a MUD URL
       is found, log it and validate the MUD URL.

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    found_url = 0 
                    
    mud_ouit = str.join('',('%c'% i for i in (0x00, 0x00, 0x5e, 0x01)))
    
    for timestamp, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)

        if isinstance(eth.data, dpkt.lldp.LLDP):
            lldp = eth.data
            for tlv in lldp.tlvs:
                tlv_type = tlv.typelen >> 9
                tlv_len = tlv.typelen & 0x01ff
                if tlv_type == 127:
                    oui_type = str.join('',('%c'% i for i in tlv.data[:4]))
                    if oui_type == mud_ouit:
                        mud_url = str.join('',('%c'% i for i in (tlv.data[4:])))
                        found_url = 1
                        log_eth_packet(timestamp, eth)
                        validate_mud_url(mud_url, 'LLDP')
            continue

        #
        # Look for IP/UDP#/DHCP packets
        #
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data
        if not isinstance(ip.data, dpkt.udp.UDP):
            continue
      
        msg_type = 'none'
        udp = ip.data
        if udp.sport == 68 and udp.dport == 67:
            dhcp = dpkt.dhcp.DHCP(udp.data)
            for opt in dhcp.opts:
                if opt[0] == 53:
                    if opt[1] == b'\x01':
                        msg_type = 'DHCP Discover'
                    elif opt[1] == b'\x03':
                        msg_type = 'DHCP Request'
                    else:
                        break;
                elif opt[0] == 161:
                    found_url = 1
                    log_dhcp_packet(timestamp, eth, msg_type)
                    mud_url = str.join('',('%c'% i for i in (opt[1][0:])))
                    validate_mud_url(mud_url, 'DHCP')
            if msg_type == 'none':
                continue

    if found_url == 0:
        print('No MUD URL found in the pcap file.')


def validate_pcap_mud_url():
    # Setup command arguments. The filename is a required argument.
    parser = argparse.ArgumentParser(prog='validate_mud_url', description=
                'Find MUD URLs in a PCAP file.')
    parser.add_argument('-v', '--version', action='version', 
                        version='%(prog)s 1.0')
    parser.add_argument("filename", help='PCAP file to check for MUD URLs')
    args = parser.parse_args()

    # Validate that the filename ends in .pcap
    if not args.filename.endswith('.pcap'):
        print('ERROR: Filename should end in .pcap')
        return

    # Open up a test pcap file and check packets
    with open(args.filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
    
        print('\nANALYZING', args.filename)

        find_mud_url(pcap)


def test():
    print('TESTING VALIDATION RULES')

    print('  SHOULD PASS VALIDATION')
    # Examples from the MUD specification
    validate_mud_url('https://things.example.org/product_abc123/v5', 'TEST')
    print('\n')
    validate_mud_url('https://www.example.net/mudfiles/temperature_sensor/',
                      'TEST')
    print('\n')
    validate_mud_url('https://example.com/lightbulbs/colour/v1', 'TEST')
    print('\n  SHOULD FAIL VALIDATION')
    validate_mud_url('https://www.foo.com/hello/there.json', 'TEST')
    print('\n')
    validate_mud_url('http://www.foo.com/hello/there/', 'TEST')
    print('\n')
    validate_mud_url('https://www.foo.com&hello*there.json', 'TEST')
    print('\n')
    validate_mud_url('https://www.foo.com/<begin>/<mudfile>/<end>/.json', 'TEST')


if __name__ == '__main__':
    #test()
    validate_pcap_mud_url()

#!/usr/bin/env python

""" validate_mud_url.py
Use this script to find MUD URLs in LLDP and DHCP packets found in a pcap file.
FUTURE: If a MUD URL is not found, check the other TLVs or options or TLVs 
        to see if there is a malformed MUD URL in recognizable way.

Copyright (c) 2018 Cisco and/or its affiliates.
"""

from __future__ import print_function

import datetime
import socket
import validators
import argparse
import os
import sys
import wget
import dpkt.radius
from dpkt.radius import *
from dpkt.dhcp import *
import dpkt

iana_oui = str.join('',('%c'% i for i in (0x00, 0x00, 0x5e)))
tr41_oui = str.join('',('%c'% i for i in (0x00, 0x12, 0xbb)))
ieee8023_oui = str.join('',('%c'% i for i in (0x00, 0x12, 0x0f)))
cisco_oui = str.join('',('%c'% i for i in (0x00, 0x01, 0x42)))

oui_file = None

check_oui = True

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


def log_udp_packet(timestamp, eth, prot_type, msg_type):
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

    print('    ', prot_type, ': Message Type:', msg_type)


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

    if url.find ('.well_known') > 0:
        print('        WARNING: A MUD URI should not have a ".well_known"')
        print('                component. This was present only in early ')
        print('                drafts of the MUD specification.')

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

def is_iana_oui(timestamp, eth, tlv):
    # As globals, oui_file are treated as "static" variables.
    global oui_file
    global check_oui

    oui = str.join('',('%c'% i for i in tlv.data[:3]))

    # Check for IANA first, if so we're done.
    if oui == iana_oui: 
        return True;

    if check_oui == False:
        return False;

    # Check the IEEE 802 OUI file. If not there, issue a warning.
    if oui_file == None:
        # Use a local copy, if available in the current directory.
        # Otherwise attempt to fetch it from the IEEE 802 server.
        # TODO: Check the file time, and if it's too old fetch it anyway
        #       and cache the new copy.
        cached_oui_file = './oui.txt'
        oui_file = cached_oui_file
        if os.path.exists(oui_file):
            with open(oui_file, 'rb') as g:
                oui_file = g.read()
        else:
            oui_file = "http://standards-oui.ieee.org/oui.txt"
            print('\nFetching ', oui_file);
            cached_oui_file = wget.download(oui_file)
            
        with open(cached_oui_file, 'r') as f:
            oui_file = f.read()

    oui_str ='-'.join('%02X' % dpkt.compat.compat_ord(b) for b in tlv.data[:3])
    if oui_file.find(oui_str) < 0:
        log_eth_packet(timestamp, eth)
        print('WARNING: OUI {0} not found in IEEE 802 OUI file.'\
                    .format(oui_str))
        print('         Are you sure it is correct?')

    return False


def check_lldp_frame(timestamp, eth):
    lldp = eth.data
    exp_subtype = 1
    for tlv in lldp.tlvs:
        tlv_type = tlv.typelen >> 9
        tlv_len = tlv.typelen & 0x01ff
        if tlv_type == 127:
            # Found an Organization Specific TLV
            if is_iana_oui(timestamp, eth, tlv) == True:
                # Found an IANA OUI, but is the subtype correct (0x01)?
                subtype=ord(str.join('', ('%c' %tlv.data[3])))
                if subtype == exp_subtype:
                    mud_url = str.join('',('%c'% i for i in (tlv.data[4:])))
                    log_eth_packet(timestamp, eth)
                    validate_mud_url(mud_url, 'LLDP')
                    return True;
                else:
                    log_eth_packet(timestamp, eth)
                    print('WARNING: LLDP frame with an IANA OUI found, but')
                    print('         with a Subtype not a MUD URI.')
                    print('             Subcode={0}'.format(hex(subtype)))
                    print('         If this is meant to be a MUD URI TLV, it')
                    print('         should be:')
                    print('             Subcode={0}'.format(hex(exp_subtype)));

    return False


def check_dhcp_packet(timestamp, eth, udp):
    dhcp = dpkt.dhcp.DHCP(udp.data)
    for opt in dhcp.opts:
        if opt[0] == 53:
            if opt[1] == chr(DHCPDISCOVER):
                msg_type = 'DHCP Discover'
            elif opt[1] == chr(DHCPREQUEST):
                msg_type = 'DHCP Request'
            else:
                # We don't care about other DHCP message types
                break;
        elif opt[0] == 161:
            log_udp_packet(timestamp, eth, 'DHCP', msg_type)
            mud_url = str.join('',('%c'% i for i in (opt[1][0:])))
            validate_mud_url(mud_url, 'DHCP')
            return True

    return False

def check_radius_packet(timestamp, eth, udp):
    radius = dpkt.radius.RADIUS(udp.data)

    if radius.code == RADIUS_ACCESS_REQUEST:
        msg_type = 'Access'
    elif radius.code == RADIUS_ACCT_REQUEST:
        msg_type = 'Accounting'
    else:
        print('Unexpected {0} message'.format(hex(radius.code)))
        return;

    for attr in radius.attrs:
        # attr[0] has the type, attr[1] has the attribute data
        if attr[0] == 26:
            # For a Vendor-Specific attribute, the data begins after the
            # Vendor id (e.g., 0x00000009 for Cisco)
            tlv_data = attr[1][4:]
            # Validate that there is a 0x01 and we don't care about the next
            # octet (length).
            if tlv_data[0] == b'\x01':
                data = tlv_data[2:]
                if str.join('',('%c'% i for i in (data[0:9]))) == "lldp-tlv=":
                    #
                    # Found an LLDP TLV. See if it contains a MUD URL.
                    #   Two octets LLDP type (0x007f), followed by two octets
                    #   of length (which we ignore). Then look for the OUI
                    #   (0x00005e) and a subtype of 0x01.
                    if data[9] == b'\x00' and data[10] == b'\x7f':
                        if data[13] == b'\x00' and data[14] == b'\x00' and \
                           data[15] == b'\x5e' and data[16] == b'\x01':
                            mud_url = data[17:]
                            log_udp_packet(timestamp, eth, 'RADIUS/LLDP TLV', 
                                           msg_type)
                            validate_mud_url(mud_url, 'Radius')
                            return True
                elif str.join('',('%c'% i for i in (data[0:12]))) == \
                     "dhcp-option=":
                    #
                    # Found a DHCP Option. See if it contain a MUD URL.
                    #   Two octets DHCP option number (0x00a1), followed by
                    #   two octets of length (which we ignore). Then look for
                    #   the MUD URL.
                    #
                    if data[12] == b'\x00' and data[13] == b'\xa1':
                        mud_url = data[16:]
                        log_udp_packet(timestamp, eth, 'RADIUS/DHCP Option', 
                                       msg_type)
                        validate_mud_url(mud_url, 'Radius')
                        return True




    return False

def find_mud_url(pcap):
    """Look for a MUD URLs in frames discovered in a pcap. If a MUD URL
       is found, log it and validate the MUD URL.

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    found_url = 0 
                    
    for timestamp, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)

        if isinstance(eth.data, dpkt.lldp.LLDP):
            if check_lldp_frame(timestamp, eth):
                found_url = found_url + 1
            continue

        #
        # Look for IP/UDP/DHCP packets
        #
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not isinstance(ip.data, dpkt.udp.UDP):
            continue
        udp = ip.data
        if udp.sport == 68 and udp.dport == 67:
            if check_dhcp_packet(timestamp, eth, udp):
                found_url = found_url + 1
            continue

        #
        # Look for RADIUS packets carrying MUD URLs
        # ISE can use port 1645 or 1812 for RADIUS Authentication, and
        # port 1646 or 1813 for RADIUS Accounting.
        #
        if udp.dport == 1645 or udp.dport == 1812 or \
           udp.dport == 1646 or udp.dport == 1813:
            if check_radius_packet(timestamp, eth, udp):
                found_url = found_url + 1


    if found_url == 0:
        print('\nNo records in the pcap file seem to contain a MUD URL.')
    else:
        print('\nFound {0} MUD URLs in the pcap file.'.format(found_url))


def validate_pcap_mud_url():
    global check_oui

    # Setup command arguments. The filename is a required argument.
    parser = argparse.ArgumentParser(prog='validate_mud_url', description=
                'Find MUD URLs in a PCAP file.')
    parser.add_argument('-v', '--version', action='version', 
                        version='%(prog)s 1.0')
    parser.add_argument('-s', '--skipoui', action='store_true')
    parser.add_argument("filename", help='PCAP file to check for MUD URLs')
    args = parser.parse_args()

    # Validate that the filename ends in .pcap
    if not args.filename.endswith('.pcap'):
        print('ERROR: Filename should end in .pcap')
        return

    check_oui = not args.skipoui 

    # Open up a test pcap file and check packets
    with open(args.filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
    
        print('\nANALYZING', args.filename)

        find_mud_url(pcap)


def test():
    print('TESTING VALIDATION RULES')

    print('  SHOULD PASS VALIDATION WITHOUT WARNINGS')
    # Examples from the MUD specification
    validate_mud_url('https://things.example.org/product_abc123/v5', 'TEST')
    print('\n')
    validate_mud_url('https://www.example.net/mudfiles/temperature_sensor/',
                      'TEST')
    print('\n')
    validate_mud_url('https://example.com/lightbulbs/colour/v1', 'TEST')
    print('\n  SHOULD PASS VALIDATION WITH WARNINGS')
    validate_mud_url('https://example.com/.well_known/v1/lightbulbs/colour/v1', 'TEST')
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

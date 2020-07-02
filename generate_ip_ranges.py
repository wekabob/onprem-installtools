#!/usr/bin/env python

#
# Configure a cluster
#   Expects the hosts to be in STEM mode already
#
#   Written by Vince Fleming, vince@weka.io
#

# Dependencies: ???
# yum install epel-release
# yum install python-pip
# pip install --upgrade pip
#

#
# To do:
#
#   resolve hostnames in the input file, get their ip addresses and save them for the cluster create.
#       If the names don't resolve to the dataplane network, we need to specify the dataplane network IPs
#
#   We really need to import dns.resolver and ipaddress modules to reliably check ip addresses!
#
# 
#
#

#
# imports
#
import subprocess
from subprocess import Popen, PIPE, STDOUT
import sys
import json
import os.path
import os
from datetime import datetime
import argparse
import time
import re

###################################################################################################################
#
# Functions
#
try:
    input = raw_input
except NameError:
    pass

def prompt( message, default_answer, errormessage, isvalid, isvalid_arg ):
    res = None
    while res is None:
        if default_answer is not None:
            res = input(str(message)+ '(' + str(default_answer) + '): ')
        else:
            res = input(str(message)+ ': ')

        if (len(res) == 0) and default_answer is not None:
            res = default_answer
        if not isvalid( res, isvalid_arg ):
            print str(errormessage)
            res = None
    return res

def prompt_yn( message, default_answer ):
    response = prompt( message, default_answer, "\tPlease respond Y/y or N/n", checkyn, None )
    if response.lower() == "y":
        return True
    else:
        return False

def checknum( answer, junk ):
    if int( answer ) > 0:
	return True
    return False
     

def ip_to_int( ipaddr_str ):
    parts = ipaddr_str.split( '.' )
    return (int( parts[0] ) << 24) + (int( parts[1] ) << 16) + (int( parts[2] ) << 8) + int( parts[3] )

def int_to_ip( ipaddr_int ):
    return str( ipaddr_int >> 24 ) + "." + str( (ipaddr_int & (255 << 16)) >> 16) + "." + str( (ipaddr_int & (255 << 8)) >> 8 ) + "."  + str( ipaddr_int & 255 )

def network_ip( ipaddr, maskbits ):
    int_ipaddr = ip_to_int( ipaddr )
    mask = (int( "0xffffffff", 16 ) >> (32-maskbits)) << (32-maskbits)
    return int_to_ip( int_ipaddr & mask )

def iprange_startip( ip_range ):
    splits = ip_range.split( "-" )		# "192.168.1.2-3.14" -> ["192.168.1.2", "3.14"]
    return( splits[0] )

def iprange_endip( ip_range ):
    splits = ip_range.split( "-" )		# "192.168.1.2-3.14" -> ["192.168.1.2", "3.14"]
    int_ipaddr_base = ip_to_int( splits[0] )
    base_octet_list = splits[0].split( "." )	# "192.168.1.2" -> ["192", "168", "1", "2"]
    if len( splits ) > 1:
        end_octet_list = splits[1].split( "." )	# "3.14" -> ["3", "14"]
        num_octets = len( end_octet_list )
        end_ip = []

        # reverse the lists/addresses to make this easier
        end_octet_list.reverse()
        base_octet_list.reverse()

        for octet in end_octet_list:
            end_ip.append( octet )
        for octet in base_octet_list:
            if num_octets > 0:
                num_octets -= 1
            else:
                end_ip.append( octet )
        return end_ip[3] + "." + end_ip[2] + "." + end_ip[1] + "." + end_ip[0]
    else:
        return ip_range


def iprange_num_ips( ip_range ):
    return ip_to_int( iprange_endip( ip_range ) ) - ip_to_int( iprange_startip( ip_range ) ) + 1



def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

def is_valid_range(ip):
    """Validates IPv4 ranges of addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          # Dotted variants with ranges:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}                # base ip ends here
          (?:                  # Repeat 0-3 times, separated by a dash
            \-
              (?:
                # Decimal 1-255 (no leading 0's)
                [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
              |
                0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
              |
                0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
              )
              (?:                  # Repeat 0-3 times, separated by a dot
                \.
                (?:
                  [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
                |
                  0x0*[0-9a-f]{1,2}
                |
                  0+[1-3]?[0-7]{0,2}
                )
              ){0,3}
          )
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None
 

#
#   This should be significantly fancier... things to improve are:
#       verify that the ips given are on the same network as the hosts' interfaces
#       verify (with netmask) that the range given is valid (are they on the same network?)
#
#       verify that the end address is greater than the base address - done (getting the number of ips does this)
#               if the end address is not greater than the base, the number of addresses would be negative
#       check that there are enough addresses - done
#
#
def checkiprange( answer, min_num_addresses ):
    if not is_valid_range( answer ):
        return False

    if min_num_addresses != None:
        if iprange_num_ips( answer ) < min_num_addresses:
            print "insufficient number of addresses specified."
            return False

    return True

def checkvalidip( answer, junk ):
    return is_valid_ipv4( answer )

# print something without a newline
def announce( text ):
    sys.stdout.flush()
    sys.stdout.write(text)
    sys.stdout.flush()

###################################################################################################################
#
# main()
#


baseip = prompt( "Enter a base IP address format a.b.c.d", "", "Invalid syntax, try again", checkiprange, None )
step = int( prompt( "Enter the number of ips per range", "", "Invalid syntax, try again", checknum, None ) )
count = int( prompt( "Enter the number ranges (hosts)", "", "Invalid syntax, try again", checknum, None ) )

baseip_int = ip_to_int( baseip )

# output should be "10.36.1.1-15"
while count > 0:
    endip = baseip_int + step -1
    endip_str = int_to_ip( endip )
    endlist = endip_str.split( "." )
    endoctet = endlist[3]

    range = int_to_ip( baseip_int ) + "-" + endoctet
    if iprange_num_ips( range ) < step:			# went over a Class-C boundry - weka gets upset at this
        baseip_int = endip + 1
	continue					# repeat this range

    print range

    baseip_int = endip + 1
    count -= 1






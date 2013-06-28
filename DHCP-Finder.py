#!/usr/bin/env python

#DHCP-Finder
#Purpose: To find any and all DHCP servers out on the network and report back.
#Version: 1.0
#By: Michael Contino
#Contact: @sleventyeleven

#Import required stuff
from scapy.all import *

#set fixes to get addtional infromation and multiple responses
conf.checkIPaddr = False
fam,hw = get_if_raw_hwaddr(conf.iface)

#craft a DHCP discover Packet to find all DHCP servers
p=Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"]) # Making the packet :)

#catch an responses in 30 seconds
ans, unans = srp(p, multi=True, timeout=30)

#start the loop to parse any caught answers
for a in ans:
    #display the Mac and IP address of 
    print a[1][Ether].src, a[1][IP].src

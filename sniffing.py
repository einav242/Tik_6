#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

#pkt = sniff(iface=['lo','enp0s3'],filter='icmp', prn=print_pkt) #ping 8.8.8.8
#pkt = sniff(iface=['lo','enp0s3'],filter='tcp and src host 10.0.2.15 and dst port 23', prn=print_pkt) #telnet 8.8.8.8
pkt = sniff(iface=['lo','enp0s3'],filter='dst net 128.230.0.0/16', prn=print_pkt) #ping 128.230.1.2




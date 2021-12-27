from scapy.all import *
from scapy.layers.inet import ICMP, IP

a = IP()
a.dst = "10.0.2.3"
b = ICMP()
p = a/b
send(p)

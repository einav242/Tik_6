from scapy.all import *

a = IP() 
a.dst='10.0.2.15'
a.src='8.8.8.8'
b=ICMP()
p=a/b
send(p)

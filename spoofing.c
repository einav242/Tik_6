#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>



struct icmp_header {
  unsigned char type; 
  unsigned char error_code; 
  unsigned short int check_sum; 
  unsigned short int id;    
  unsigned short int seq;    
};


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


void send_packet(struct ip_header* ip)
{
    struct sockaddr_in dest;
    int e = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&e, sizeof(e));

    dest.sin_family = AF_INET;
    dest.sin_addr = ip->ip_dest;

    printf("Sending...\n");
    if (sendto(sock, ip, ntohs(ip->ip_headr_len), 0,(struct sockaddr *)&dest, sizeof(dest)) < 0){
    	fprintf(stderr, " the function sendto() failed with error: %d", errno);
    	}
    	else{
    	printf("spofing packet: \n");
    	printf("src: %s\n", inet_ntoa(ip->ip_src));
    	printf("dest: %s\n", inet_ntoa(ip->ip_dest));
    	printf("---------------------------\n");
	}
    close(sock);
}


unsigned short check_sum (unsigned short *buf, int length)
{
   int sum = 0;
   unsigned short temp=0;
   unsigned short *temp_buf= buf;
   int temp_len;
   for(temp_len=length;temp_len>1;temp_len-=2)
    {
       sum += *temp_buf;
       temp_buf+=1;
    }
   if (temp_len== 1) {
        *(u_char *)(&temp) = *(u_char *)temp_buf ;
        sum += temp;
   }
   sum = (sum >> 16) + (sum & 0xffff); 
   sum += (sum >> 16);                 
   return (unsigned short)(~sum);
}



int main(){
	char buffer[1024]; 
	memset(buffer, 0, 1024);
	
	struct icmp_header *icmp = (struct icmp_header *) (buffer + sizeof(struct ip_header));

	icmp->type = 8;

	icmp->check_sum = 0;
	icmp->check_sum = check_sum((unsigned short *)icmp, sizeof(struct icmp_header));

	struct ip_header *ip = (struct ip_header*) buffer;
	ip->ip_version = 4;
	ip->ip_headr_len = 5;
	ip->ip_type = 16;
	ip->ip_ttl = 20;
	ip->ip_src.s_addr = inet_addr("8.8.8.8");
	ip->ip_dest.s_addr = inet_addr("192.168.1.25");
	ip->ip_proto = IPPROTO_ICMP;
	ip->ip_packet_len = htons(sizeof(struct ip_header) + sizeof(struct icmp_header));
	
	send_packet(ip);
	
	return 0;
}




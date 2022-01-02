#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include "headers.h"

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




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

struct icmp_header {
  unsigned char type; 
  unsigned char error_code; 
  unsigned short int check_sum; 
  unsigned short int id;    
  unsigned short int seq;    
};

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

struct tcp_header {
    u_short tcp_src;               
    u_short tcp_dest;               
    u_int   tcp_seq_num;                
    u_int   tcp_ack_num;                 
    u_char  tcp_offx2;               
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
    u_short tcp_window;                 
    u_short tcp_sum;                 
    u_short tcp_urg_pointer;                 
};

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
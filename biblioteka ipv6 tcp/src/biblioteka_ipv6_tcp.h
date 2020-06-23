#ifndef BIBLIOTRKA_IPV4_H_
#define BIBLIOTRKA_IPV4_H_

struct ethh{
	unsigned char MAC_des1;
	unsigned char MAC_des2;
	unsigned char MAC_des3;
	unsigned char MAC_des4;
	unsigned char MAC_des5;
	unsigned char MAC_des6;
	unsigned char MAC_src1;
	unsigned char MAC_src2;
	unsigned char MAC_src3;
	unsigned char MAC_src4;
	unsigned char MAC_src5;
	unsigned char MAC_src6;
	unsigned short type;
};

struct ipv6h{
	unsigned char version: 4;
	unsigned char Traffic_Class;
	unsigned int flow_Label: 12;
	unsigned short payload_Length;
	unsigned char next_Header;
	unsigned char hop_Limit;
	unsigned char IPsrc[16];
//	unsigned long IPsource1;
//	unsigned long IPsource2;
	unsigned char IPdst[16];
//	unsigned long IPdest1;
//	unsigned long IPdest2;

};

struct pseudoTCPPacket {
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t TCP_len;
};


struct lista{
	struct ethh *ETH;
	struct ipv6h *IP;
	struct tcphdr *TCP;
	struct lista *Head;
	struct lista *past;
	struct lista *present;
	struct lista *next;
};


unsigned short csum(unsigned short *ptr,int nbytes);
void setETH(struct ethh *ETH, char interface[]);
void setIPv6(struct ipv6h *IP);
void setTCP(struct tcphdr *tcpHdr);
struct lista * toTheList(struct ethh *eth, struct ipv6h *ip, struct tcphdr *tcpHdr);
void send_packet(struct lista *list, char interface[]);

#endif /* BIBLIOTRKA_IPV4_H_ */

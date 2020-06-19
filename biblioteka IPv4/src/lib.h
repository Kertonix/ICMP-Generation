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

struct iph{
	unsigned char version :4;
	unsigned char IHL :4;
	unsigned char DSCP :6;
	unsigned char ECN :2;
	unsigned short totalLength;
	unsigned short identification;
	unsigned char R :1 ;
	unsigned char DF :1;
	unsigned char MF :1;
	unsigned int offset :13;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short controlSum;
	unsigned char IPsource1;
	unsigned char IPsource2;
	unsigned char IPsource3;
	unsigned char IPsource4;
	unsigned char IPdest1 ;
	unsigned char IPdest2 ;
	unsigned char IPdest3 ;
	unsigned char IPdest4  ;
};

struct icmph {
	unsigned char type;
	unsigned char code;
	unsigned short sum ;
	unsigned short identifier;
	unsigned short sequence_nr;
//	long int rest :32;
};


struct lista{
	struct ethh *ETH;
	struct iph *IP;
	struct icmph *ICMP;
	struct lista *Head;
	struct lista *past;
	struct lista *present;
	struct lista *next;
};


unsigned short csum(unsigned short *ptr,int nbytes);
void setETH(struct ethh *ETH, char interface[]);
void setIP(struct iph *IP);
void setICMP(struct icmph *ICMP);
struct lista * toTheList(struct ethh *eth, struct iph *ip, struct icmph *icmp);
void send_packet(struct lista *list, char interface[]);

#endif /* BIBLIOTRKA_IPV4_H_ */

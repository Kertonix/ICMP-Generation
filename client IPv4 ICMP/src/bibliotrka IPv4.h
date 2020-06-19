/*
 * bibliotrka IPv4.h
 *
 *  Created on: Apr 11, 2020
 *      Author: root
 */

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
	unsigned short type ;

};

struct iph{
	unsigned char version :4;
	unsigned char IHL :4;
	unsigned char DSCP :6;
	unsigned char ECN :2;
	unsigned short totalLength;
	unsigned short identyfication;
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
	unsigned char type :8;
	unsigned char code :8;
	int sum :16;
	long int rest :32;
};


struct lista{
	struct lista *forHead;
	struct lista *past;
	struct lista *present;
	struct lista *next;
	struct ethh *forETH;
	struct iph *forIP;
	struct udph *forUDP;
};

void setETH(struct ethh *ETH);
void setIP(struct iph *IP);
void setICMP(struct iph *IP, struct icmph *ICMP);
struct lista * toTheList(struct ethh *eth, struct iph *ip, struct icmph *icmp);
void sendpacket(struct lista *list);

#endif /* BIBLIOTRKA_IPV4_H_ */

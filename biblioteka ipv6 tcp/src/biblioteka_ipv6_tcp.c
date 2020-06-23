#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include "biblioteka_ipv6_tcp.h"
#include <netinet/ip6.h>      // struct ip6_hdr
#include <linux/tcp.h>      // struct tcp_hdr



char inter[15];

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

void send_packet(struct lista *list, char interface[]){
	int size=71;

	interface=inter;

	int sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
		if(sock_raw == -1)
			printf("error in socket");

	struct ifreq ifreq_i;
	memset(&ifreq_i,0,sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name,interface,IFNAMSIZ-1);
	//pobieranie indexu interfejsu po nazwie (bo interfejsy są normalnie poprostu numerkami)
	if((ioctl(sock_raw,SIOCGIFINDEX,&ifreq_i))<0)
	printf("error in index ioctl reading");//getting Index Name
	//printf("index=%d\n",ifreq_i.ifr_ifindex); // wyświetlanie index name

	struct ifreq ifreq_c;
	memset(&ifreq_c,0,sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name,interface,IFNAMSIZ-1);//giving name of Interface

	if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0) //getting MAC Address
	printf("error in SIOCGIFHWADDR ioctl reading");

	struct ifreq ifreq_ip;
	memset(&ifreq_ip,0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name,interface,IFNAMSIZ-1);//giving name of Interface
	if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0){ //getting IP Address
		printf("error in SIOCGIFADDR \n");
	}

	unsigned char *sendbuff=(unsigned char*)malloc(size); //alokacja pamieci bufora o zmiennym rozmiarze
	memset(sendbuff,0,size);
	int i;

//	uzupełnianie bufora

//	coś to nie działa \/ :(
//	memcpy(sendbuff, &list, sizeof(list->ETH)+sizeof(list->IP)+sizeof(list->tcp));

//	ETH
	sendbuff[0]= list->ETH->MAC_des1;
	sendbuff[1]= list->ETH->MAC_des2;
	sendbuff[2]= list->ETH->MAC_des3;
	sendbuff[3]= list->ETH->MAC_des4;
	sendbuff[4]= list->ETH->MAC_des5;
	sendbuff[5]= list->ETH->MAC_des6;

	sendbuff[6]= list->ETH->MAC_src1;
	sendbuff[7]= list->ETH->MAC_src2;
	sendbuff[8]= list->ETH->MAC_src3;
	sendbuff[9]= list->ETH->MAC_src4;
	sendbuff[10]= list->ETH->MAC_src5;
	sendbuff[11]= list->ETH->MAC_src6;

	i = list->ETH->type;
	i = i >> 8;
	sendbuff[12] = i;
	sendbuff[13] = list->ETH->type;

//	IP
	sendbuff[14]=list->IP->version;
	sendbuff[14]=sendbuff[14]<<4;
	i=list->IP->Traffic_Class;
	i=i>>4;
	sendbuff[14] = sendbuff[14] + i;
	sendbuff[15] = list->IP->Traffic_Class;
	sendbuff[15] = sendbuff[15] << 4;
	i=list->IP->flow_Label;
	i=i>>16;
	sendbuff[15]= sendbuff[15] + i;
	i=list->IP->flow_Label;
	i=i>>8;
	sendbuff[16]= sendbuff[16] + i;
	sendbuff[17]= list->IP->flow_Label;

	i=list->IP->payload_Length;
	i=i>>8;
	sendbuff[18]= i;
	sendbuff[19]= list->IP->payload_Length;
	sendbuff[20]= list->IP->next_Header;
	sendbuff[21]= list->IP->hop_Limit;

	for(i=0; i<16;i++){
	sendbuff[22+i]= list->IP->IPsrc[i];
	}
	for(i=0; i<16;i++){
	sendbuff[38+i]= list->IP->IPdst[i];
	}


//	TCP
	memcpy(&sendbuff[55],list->TCP,16);

//		uint16_t help16;
//		help16=htons(list->TCP->source);
//		memcpy(&sendbuff[55],&help16,2);
//		help16=htons(list->TCP->dest);
//		memcpy(&sendbuff[56],&help16,2);
//
//
//		uint32_t help32;
//		help32=htonl(list->TCP->seq);
//		memcpy(&sendbuff[57],&help32,4);
//
//		help32=htonl(list->TCP->ack_seq);
//		memcpy(&sendbuff[57],&help32,4);


//	pobieranie mac interfejsu
	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
	sadr_ll.sll_addr[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
	sadr_ll.sll_addr[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
	sadr_ll.sll_addr[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
	sadr_ll.sll_addr[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
	sadr_ll.sll_addr[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
	sadr_ll.sll_addr[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);
	int send_len;
	int counter = 0;

//	wysyłamy pakiety dopóki sie nie skonczy lista a ponieważ wszystkie elementy są takie same to
//	bufor można uzupełnić tylko raz, nie trzeba przepisywać tego samego cały czas
	while(list){
	send_len = sendto(sock_raw,sendbuff,size,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
		if(send_len<0){
			printf("error in sending....sendlen=%d....\n",send_len);
			break;
		}
	list = list->next;
	counter++;
	}
	if(list==NULL)
	printf("%d pakietow zostalo wyslane\n",counter);
}

struct lista * toTheList(struct ethh *eth, struct ipv6h *ip, struct tcphdr *tcpHdr){
	puts("\nIle razy wyslac pakiet?");
	unsigned int ilerazy;
	scanf("%u",&ilerazy);
	if(ilerazy == 0){
		puts("0 to za mało, wyślę raz");
		ilerazy = 1;
	}
//	przypadek tworzenia jednoelementowej listy
	if(ilerazy == 1){
		struct lista *HEAD;
		HEAD = (struct lista*)malloc(sizeof(struct lista));
		HEAD->Head = HEAD;
		HEAD->next = NULL;
		HEAD->past = NULL;
		HEAD->ETH = eth;
		HEAD->IP = ip;
		HEAD->TCP = tcpHdr;
//		puts("lista OK");
		return HEAD;
	}
//	przypadek listy wiazanej
	else{
//		tworzymy pierwszy element
		struct lista *HEAD;
		struct lista *NEW;
		struct lista *PAST;
		HEAD = (struct lista*)malloc(sizeof(struct lista));
		PAST = (struct lista*)malloc(sizeof(struct lista));
		HEAD->Head = HEAD;
		HEAD->next = NULL;
		HEAD->past = NULL;
		HEAD->ETH = eth;
		HEAD->IP = ip;
		HEAD->TCP = tcpHdr;
		PAST = HEAD;
//		a resztę wiadomo, pętlą
		for(int i = 2; i <=ilerazy; i ++){
			NEW = (struct lista*)malloc(sizeof(struct lista));
			NEW->ETH = eth;
			NEW->IP = ip;
			NEW->TCP = tcpHdr;
			NEW->Head = HEAD;
			NEW->next = NULL;
			if(i==2){
				HEAD->next = NEW;
			}else{
				PAST->next = NEW;
			}
			PAST = NEW;
		}
//		zwracamy wskaźnik na początek listy
//		puts("lista OK");
		return HEAD;
	}
}

void setETH(struct ethh *ETH, char interface[]){
	puts("\nPodaj nazwe interfejsu z ktorego wyslac wiadomosc:\n");
	scanf("%s",inter);
	interface=inter;

	// pobieranie informacji o adresie źródła.
	int sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
	if(sock_raw == -1)
	printf("error in socket");

	struct ifreq ifreq_c;
	memset(&ifreq_c,0,sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name,interface,IFNAMSIZ-1);//giving name of Interface

	if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0) //getting MAC Address
	printf("error in SIOCGIFHWADDR ioctl reading");

	int i;
	puts("Przypisywanie adresów MAC: \n");
	ETH->MAC_src1 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
	ETH->MAC_src2 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
	ETH->MAC_src3 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
	ETH->MAC_src4 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
	ETH->MAC_src5 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
	ETH->MAC_src6 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);


	//robocza pętla
	ETH->MAC_des1 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
	ETH->MAC_des2 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
	ETH->MAC_des3 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
	ETH->MAC_des4 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
	ETH->MAC_des5 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
	ETH->MAC_des6 = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

//	puts("\nPodaj adres MAC celu:\n");
//	puts("Pierwszy człon zapisz i zatwierdź enterem");
//	scanf("%x",&i);
//	ETH->MAC_des1 = (unsigned char)i;
//	puts("Drugi człon zapisz i zatwierdź enterem");
//	scanf("%x",&i);
//	ETH->MAC_des2 = (unsigned char)i;
//	puts("Trzeci człon zapisz i zatwierdź enterem");
//	scanf("%x",&i);
//	ETH->MAC_des3 = (unsigned char)i;
//	puts("Czwarty człon zapisz i zatwierdź enterem");
//	scanf("%x",&i);
//	ETH->MAC_des4 = (unsigned char)i;
//	puts("Piąty człon zapisz i zatwierdź enterem");
//	scanf("%x",&i);
//	ETH->MAC_des5 = (unsigned char)i;
//	puts("Szósty człon zapisz i zatwierdź enterem");
//	scanf("%x",&i);
//	ETH->MAC_des6 = (unsigned char)i;

	//przypisanie typu
	ETH->type = 0x86DD;
//	ETH->type = ETH->type << 8;
	//Wypisanie adresów MAC
	printf("\nAdres źródłowy MAC: \n %x:%x:%x:%x:%x:%x",ETH->MAC_src1,ETH->MAC_src2,ETH->MAC_src3,ETH->MAC_src4,ETH->MAC_src5,ETH->MAC_src6);
	printf("\nAdres docelowy MAC: \n %x:%x:%x:%x:%x:%x",ETH->MAC_des1,ETH->MAC_des2,ETH->MAC_des3,ETH->MAC_des4,ETH->MAC_des5,ETH->MAC_des6);
//	printf("\nTyp: %d\n",ETH->type>>8); //wypisanie typu
	printf("\nTyp: %d\n",ETH->type); //wypisanie typu


}

void setIPv6(struct ipv6h *IP){

// pobieranie informacji o adresie IP
	int sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
	if(sock_raw == -1)
	printf("error in socket");
	struct ifreq ifreq_ip;
	memset(&ifreq_ip,0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name,"ens33",IFNAMSIZ-1);//giving name of Interface
	if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0) //getting IP Address
	{
	printf("error in SIOCGIFADDR \n");
	}


	unsigned char input[16];

	IP->version = 6; // ipv6
	IP->Traffic_Class = 0;
	IP->flow_Label = 0; // best effort

	IP->payload_Length = 17; // 40 IP + 17 TCP
	IP->next_Header=6;
	IP->hop_Limit=10;

	puts("Podaj adres źródłowy:");
	scanf("%x",input);
	strcpy(IP->IPsrc,input);
//	strcpy(IP->IPsrc,"123");


	puts("Podaj adres docelowy:");
	scanf("%x",input);
	strcpy(IP->IPdst,input);
//	strcpy(IP->IPdst,"321");



}

void setTCP(struct tcphdr *tcpHdr){
	int srcPort=0;
	int dstPort=0;

	puts("Podaj port źródłowy:");
	scanf("%d",&srcPort);
	tcpHdr->source = htons(srcPort);	/* Port źródłowy */
	tcpHdr->source = 12;

	puts("Podaj port docelowy:");
	scanf("%d",&dstPort);
	tcpHdr->dest = htons(dstPort);		/* Port docelowy */
	tcpHdr->dest = 21;

	tcpHdr->seq = 0x0; 					/* Numer sekwencji */
	tcpHdr->ack_seq = 0x0; 				/* Numer potwierdzenia */
	tcpHdr->doff = 5; 					/* Przesunięcie */
	tcpHdr->res1 = 0; 					/* Flagi TCP */
	tcpHdr->cwr = 0;
	tcpHdr->ece = 0;
	tcpHdr->urg = 0;
	tcpHdr->ack = 0;
	tcpHdr->psh = 0;
	tcpHdr->rst = 0;
	tcpHdr->syn = 1;
	tcpHdr->fin = 0;
	tcpHdr->window = htons(155); 		/* Długość danych TCP */
	tcpHdr->check = 0; 					/* Suma kontrolna TCP - liczona w programie głównym z wykorzystaniem pseudonagłówka TCP */
	tcpHdr->urg_ptr = 0;
}

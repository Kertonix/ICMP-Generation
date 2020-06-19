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
#include<linux/sockios.h>
#include  "lib.h"

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
	int size=42;

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
//	memcpy(sendbuff, &list, sizeof(list->ETH)+sizeof(list->IP)+sizeof(list->ICMP));

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
	sendbuff[14] = list->IP->version;
	sendbuff[14] = sendbuff[14] << 4;
	sendbuff[14] = sendbuff[14] + list->IP->IHL;
	sendbuff[15] = list->IP->DSCP;
	sendbuff[15] = sendbuff[15] << 2;
	sendbuff[15] = sendbuff[15] + list->IP->ECN;
	i = list->IP->totalLength;
	i = i >> 8;
	sendbuff[16] = i;
	sendbuff[17] = list->IP->totalLength;
	i = list->IP->identification;
	i = i >> 8;
	sendbuff[18] = i;
	sendbuff[19] = list->IP->identification;
	sendbuff[20] = list->IP->R;
	sendbuff[20] = sendbuff[20] << 1;
	sendbuff[20] = sendbuff[20] + list->IP->DF;
	sendbuff[20] = sendbuff[20] << 1;
	sendbuff[20] = sendbuff[20] + list->IP->MF;
	sendbuff[20] = sendbuff[20] << 5;
	i = list->IP->offset;
	i = i >> 8;
	sendbuff[20] = sendbuff[20] + i;
	sendbuff[21] = list->IP->offset;
	sendbuff[22] = list->IP->TTL;
	sendbuff[23] = list->IP->protocol;
	i = list->IP->controlSum;
	i = i >> 8;
	sendbuff[24] = i;
	sendbuff[25] = list->IP->controlSum;

	sendbuff[26] = list->IP->IPsource1;
	sendbuff[27] = list->IP->IPsource2;
	sendbuff[28] = list->IP->IPsource3;
	sendbuff[29] = list->IP->IPsource4;

	sendbuff[30] = list->IP->IPdest1;
	sendbuff[31] = list->IP->IPdest2;
	sendbuff[32] = list->IP->IPdest3;
	sendbuff[33] = list->IP->IPdest4;

	//ICMP
	sendbuff[34] = list->ICMP->type;
	sendbuff[35] = list->ICMP->code;

	i = list->ICMP->sum;
	i = i >> 8;
	sendbuff[36] = i;
	sendbuff[37] = list->ICMP->sum;
	i = list->ICMP->identifier;

	i = i >> 8;
	sendbuff[38] = i;
	sendbuff[39] = list->ICMP->identifier;

	i = list->ICMP->sequence_nr;
	i = i >> 8;
	sendbuff[40] = i;
	sendbuff[41] = list->ICMP->sequence_nr;


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

struct lista * toTheList(struct ethh *eth, struct iph *ip, struct icmph *icmp){
	puts("\nIle razy wyslac pakiet ?");
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
		HEAD->ICMP = icmp;

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
		HEAD->ICMP = icmp;
		PAST = HEAD;
//		a resztę wiadomo, pętlą
		for(int i = 2; i <=ilerazy; i ++){
			NEW = (struct lista*)malloc(sizeof(struct lista));
			NEW->ETH = eth;
			NEW->IP = ip;
			NEW->ICMP = icmp;
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
		return HEAD;
	}
}

void setETH(struct ethh *ETH, char interface[]){
//	interface="ens33";

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
	ETH->type = 8;
	ETH->type = ETH->type << 8;
	//Wypisanie adresów MAC
	printf("\nAdres źródłowy MAC: \n %x:%x:%x:%x:%x:%x",ETH->MAC_src1,ETH->MAC_src2,ETH->MAC_src3,ETH->MAC_src4,ETH->MAC_src5,ETH->MAC_src6);
	printf("\nAdres docelowy MAC: \n %x:%x:%x:%x:%x:%x",ETH->MAC_des1,ETH->MAC_des2,ETH->MAC_des3,ETH->MAC_des4,ETH->MAC_des5,ETH->MAC_des6);
	printf("\nTyp: %d\n",ETH->type>>8); //wypisanie typu

}

void setIP(struct iph *IP){

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

//	zmienne pomocnicze
	int i;
	short s;

	IP->version = 4; // ipv4
	IP->IHL = 5;
	IP->DSCP = 0; // best effort
	IP->ECN = 0; // domyślne

	//długość
	IP->totalLength = 28; // 20 IP + 8 ICMP na szytwno bez danych

	//pole identyfikacji
//	puts("Uzupelnij pole identyfikacji");
	IP->identification = 0;
//	scanf("%hx",&s);
//	IP->identification = s;

	//Flagi
	IP->R =0; // nie używana zostaje wyzerowana
//	puts("DF: 0 - zezwala na fragmentacje, 1 - nie zezwala");
//	scanf("%d",&i);
//		while((i!=0)&&(i!=1)){
//			puts("musi być 0, albo 1 - ustawiasz bit");
//			scanf("\n%d",&i);
//		}
//		IP->DF = i;

	IP->DF = 0;
	IP->MF = 0;

	IP->offset = 0;

	IP->TTL = 10;
//	puts("TTL");
//	scanf("\n%d",&i);
//	IP->TTL = i;

	IP->protocol = 1;	//ICMP

		IP->IPsource1=1;
		IP->IPsource2=1;
		IP->IPsource3=1;
		IP->IPsource4=1;

		IP->IPdest1=1;
		IP->IPdest2=1;
		IP->IPdest3=1;
		IP->IPdest4=1;

	// tutaj adresy IP
	puts("Przypisywanie adresów IP ");
	puts("Podaj IP zrodła:");
	puts("Podawaj adresy członami, enteruj \nPierwszyCzłon->DrugiCzłon->TrzeciCzłon->CzwartyCzłon");
	puts("Pierwszy człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPsource1);
	puts("Drugi człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPsource2);
	puts("Trzeci człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPsource3);
	puts("Czwarty człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPsource4);
	puts("Teraz adresy IP celu");

	puts("Podawaj adresy członami, enteruj \nPierwszyCzłon->DrugiCzłon->TrzeciCzłon->CzwartyCzłon");
	puts("Pierwszy człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPdest1);
	puts("Drugi człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPdest2);
	puts("Trzeci człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPdest3);
	puts("Czwarty człon zapisz i zatwierdź enterem");
	scanf("%hhu",&IP->IPdest4);


	// liczenie sumy kontrolnej
	IP->controlSum = 0;
	i = 0;
	int i1 = 0;
	int i2 = 0;
	int i3 = 0;
	int i4 = 0;

	i1 = IP->version;
	i1 = i1 << 12;
	i2 = IP->IHL;
	i2 = i2 << 8;
	i3 = IP->DSCP;
	i3 = i3 << 2;
	i4 = IP->ECN;
	i = i1 + i2 + i3 + i4 ;

	i1 = IP->totalLength;
	i2 = IP->identification;
	i = i + i1 + i2;

	i1 = IP->R;
	i1 = i1 << 15;
	i2 = IP->DF;
	i2 = i2 << 14;
	i3 = IP->MF;
	i3 = i3 <<13;
	i4 = IP->offset;
	i = i +  i1 + i2 + i3 + i4 ;

	i1 = IP->TTL;
	i1 = i1 << 8;
	i2 = IP->protocol;
	i = i + i1 + i2;

	i1 = IP->IPsource1;
	i1 = i1 << 8;
	i2 = IP->IPsource2;
	i = i + i1 + i2;

	i3 = IP->IPsource3;
	i3 = i3 << 8;
	i4 = IP->IPsource4;
	i = i + i3 + i4;

	i1 = IP->IPdest1;
	i1 = i1 << 8;
	i2 = IP->IPdest2;
	i = i +  i1 + i2;

	i3 = IP->IPdest3;
	i3 = i3 << 8;
	i4 = IP->IPdest4;
	i = i + i3 + i4;
	IP->controlSum = i;
	i = i >> 16;
	if(i>0){
		printf("\n i = %d",i);
		IP->controlSum = IP->controlSum + i;
		puts("\nprzeniesienie");
	}

	IP->controlSum = ~IP->controlSum;

		// wyswietlenie ustawień IP

	printf("wersja %d",IP->version);
	printf("\nIHL %d",IP->IHL);
	printf("\nDSCP %d",IP->DSCP);
	printf("\nECN %d",IP->ECN);
	printf("\ntotalLength %d",IP->totalLength);
	printf("\nidentyfikacja %d", IP->identification);
	printf("\nDF %d",IP->DF);
	printf("\nMF %d",IP->MF);
	printf("\noffset %d",IP->offset);
	printf("\nTTL %d", IP->TTL);
	printf("\nprotocol %d",IP->protocol);
	printf("\ncontrolsum %d",IP->controlSum);
	printf("\nIP źródła:  %d.%d.%d.%d",IP->IPsource1,IP->IPsource2,IP->IPsource3,IP->IPsource4);
	printf("\nIP celu:  %d.%d.%d.%d",IP->IPdest1,IP->IPdest2,IP->IPdest3,IP->IPdest4);
}

void setICMP(struct icmph *ICMP){

	puts("\n\n\nPrzypisanie wartości do ICMP");

	ICMP->type=8;
	ICMP->code=0;
	ICMP->identifier=1;
	ICMP->sequence_nr=1;
	ICMP->sum = 0;
//	ICMP->rest="qwerty";

	puts("Podaj typ:");
	scanf("%hhu",&ICMP->type);
//	puts("Podaj kod:");
//	scanf("%d",&ICMP->code);
//	puts("Podaj identyfikator:");
//	scanf("%d",&ICMP->identifier);
//	puts("Podaj sekwencje:");
//	scanf("%d",&ICMP->sequence_nr);

//	int sum;
//	int temp;
//	sum = ICMP->code;
//	temp = ICMP->type;
//	temp = temp << 8;
//	sum = sum + temp;
//
//	temp = sum;
//
//	temp = temp >> 16;
//
//	if(temp > 0){
//		sum = sum + temp;
//	}
//
//	sum = ~sum;
//
//	ICMP->sum = sum;

//	ICMP->sum = 0xf7fd;

	printf("rozmiar ICMP: %d",sizeof(ICMP));
	ICMP->sum = csum ((unsigned short *) ICMP,sizeof(ICMP));

		// wyświetlenie nagłówka

	printf("\nTyp ICMP %d",ICMP->type);
	printf("\nKod ICMP %d",ICMP->code);
//	printf("\nDane %d",ICMP->rest);
	printf("\nSuma kontrolna %x",ICMP->sum);

}

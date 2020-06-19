#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "bibliotrka IPv4.h"

int main() {
	int status; //zmienna statusu biblioteki

	void (*SET_ETH)(struct ethh*);
	void (*SET_IP)(struct iph*);
	void (*SET_ICMP)(struct icmph*);
	struct lista* (*THREEinONE)(struct ethh*, struct iph*, struct udph*);
	void (*SEND)(struct lista*);
	void *Biblioteka;

	//otwieranie biblioteki dynamicznej
	Biblioteka = dlopen("/home/piotr/eclipse-workspace/biblioteka IPv4/src/lib.so", RTLD_NOW);
	if(!Biblioteka)
	{
		printf ("Error opening: %s\n", dlerror());
		return(1);
	}

//	deklarowanie struktur i alokacja pamięci
	struct ethh *newETH;
	struct iph *newIP;
	struct udph *newICMP;
	struct lista *lista;
	newETH = (struct ethh*)malloc(sizeof(struct ethh));
	newIP = (struct iph*)malloc(sizeof(struct iph));
	newICMP = (struct icmph*)malloc(sizeof(struct icmph));

//	ustawianie pól pakietu, wpisywanie do listy wiązanej i wysyłanie
	SET_ETH = dlsym(Biblioteka,"setETH");
	SET_ETH(newETH);
	SET_IP = dlsym(Biblioteka, "setIP");
	SET_IP(newIP);
	SET_ICMP = dlsym(Biblioteka, "setICMP");
	SET_ICMP(newICMP);
	THREEinONE = dlsym(Biblioteka, "toTheList");
	lista = THREEinONE(newETH,newIP,newICMP);
	SEND = dlsym(Biblioteka, "send_packet");
	SEND(lista);

//	zamykanie biblioteki
	status = dlclose(Biblioteka);
	if(status) { printf("ERROR %s\n",dlerror()); return -1; }

	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

struct	wp_read_str{
	u_int8_t  ether_shost[ETH_ALEN];
	uint32_t ip_src;
	uint32_t packets;
	int encontrado;
	uint32_t length;
	unsigned char *rawData; 
	char phone[20];
	char version[20];
	//char phone[20];
	//char rawData[100];
};

pcap_handler callback(u_char *, struct pcap_pkthdr *, u_char *);

char * toHWAddress(unsigned char *hwaddress);
const char *ip_format(int ip);
void pPacket(char *data, int length);
int itemListTCP();
int addListTCP(u_int8_t *ether_shost,uint32_t ip_src);
int existListTCP(u_int8_t *ether_shost,uint32_t ip_src);
void printListTCP(int item);
void memdump(unsigned char *memoria,int length);


in_addr_t net,dest,source,mask;
struct	wp_read_str **wp_buffer;

int main(int argc,char *argv[])	{
	char *file;
	char errbuffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_data;
	if (argc < 2) { 
		fprintf(stderr, "Usage: %s [input File]\n", argv[0]); 
		exit(1); 
	}
	file = argv[1];
	pcap_data = pcap_open_offline(file, errbuffer);
	if (pcap_data == NULL) {
		fprintf(stderr, "Oops: %s\n", errbuffer);
		exit(0xDEAD);
	}
	net = inet_addr("50.22.231.32"); //WhatsApp network range /27
	mask = inet_addr("255.255.255.224"); //WhatsApp netmask
	wp_buffer = calloc(2,sizeof(struct	wp_read_str *));
	while(pcap_loop(pcap_data, -1, (pcap_handler)callback, NULL));
	return 0;
}

pcap_handler callback(u_char *datain, struct pcap_pkthdr *pktdata, u_char *pkt)	{
	int i, fromlen, bytes_received,d,datalen,datasearch;
	struct ether_header *ethhdr;
	struct iphdr *iphead;
	struct tcphdr *tcphead;
	char *data;
	ethhdr = (struct ether_header *) pkt;
	iphead = (struct iphdr *)((char *)ethhdr+sizeof(struct ether_header));
	tcphead = (struct tcphdr *)((char *)iphead+sizeof(struct iphdr));
	data = (char*)tcphead + tcphead->doff*4;
	dest = iphead->daddr & mask;
	source = iphead->saddr & mask;
	datalen = pktdata->caplen - (sizeof(struct ether_header)+iphead->ihl*4 +tcphead->doff*4);
	if (dest == net || source == net ) {
		if(existListTCP(ethhdr->ether_shost,iphead->saddr) == -1)	{
			if(tcphead->syn == 1) {
				if(tcphead->ack==0)	{					
					d = addListTCP(ethhdr->ether_shost,iphead->saddr);
				}
			}
		}
		else	{
			if(tcphead->ack == 1)	{
				d = existListTCP(ethhdr->ether_shost,iphead->saddr);
				if(datalen > 0)	{
					if(wp_buffer[d]->encontrado != 1){
						wp_buffer[d]->packets++;
						memcpy((char*)(wp_buffer[d]->rawData + wp_buffer[d]->length),data,datalen);
						wp_buffer[d]->length = wp_buffer[d]->length + datalen;
						//printf("Longitud: %d\n",wp_buffer[d]->length);
					
						if(wp_buffer[d]->length > 72)	{
							datasearch = memsearch(wp_buffer[d]->rawData,"WA",wp_buffer[d]->length,2);
							if(datasearch != -1) {
								if(wp_buffer[d]->length - datasearch > 72){
									//printf("Encontrado a: %d\n",datasearch);
									strncpy(wp_buffer[d]->version,(char*)(wp_buffer[d]->rawData+	datasearch +15),16);
									strncpy(wp_buffer[d]->phone,(char*)(wp_buffer[d]->rawData+	datasearch +58),13);
									wp_buffer[d]->encontrado=1;
									printListTCP(d);
									printf("phone: %s\n",wp_buffer[d]->phone);
									printf("version: %s\n",wp_buffer[d]->version);
									//memdump(wp_buffer[d]->rawData,wp_buffer[d]->length);
								}
							}
						}
					}
				}
			}
		}
	}
}

char * toHWAddress(unsigned char *hwaddress)	{
	static char buffer[20];
	memset(buffer,0,19);
	snprintf(buffer,19,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",hwaddress[0],hwaddress[1],hwaddress[2],hwaddress[3],hwaddress[4],hwaddress[5]);
	return buffer;
}

const char *ip_format(int ip) {
	unsigned char *fmt;
	static char buffer[18];
	memset(buffer,0,18-1);
	fmt = NULL;
	fmt = ( unsigned char *)&ip;
	snprintf(buffer,18-1,"%d.%d.%d.%d",fmt[0],fmt[1],fmt[2],fmt[3]);
	return buffer;		
}


void pPacket(char *data, int length)	{
	int i = 0;
	while(i < length)	{
		printf("%c%c%c%c",data[4*i+0],data[4*i+1],data[4*i+2],data[4*i+3]);
		i++;
	}
	printf("\n");
}

int addListTCP(u_int8_t *ether_shost,uint32_t ip_src)	{
	int item;
	item = itemListTCP();
	//printf("Item No: %d\n",item);
	wp_buffer[item] = calloc(1,sizeof(struct	wp_read_str));
	if(wp_buffer[item] == NULL)	{
		printf("Mermoria insuficiente!\n");
		exit(0xDEAD);
	}
	memcpy(wp_buffer[item]->ether_shost,ether_shost,8);
	wp_buffer[item]->ip_src = ip_src;
	wp_buffer[item]->rawData = calloc(64*1024,sizeof(char));
	wp_buffer = realloc(wp_buffer,(item+3)*sizeof(struct	wp_read_str *) );
	if(wp_buffer == NULL)	{
		printf("Mermoria insuficiente!\n");
		exit(0xDEAD);
	}
	wp_buffer[item+3] == NULL;
	return item;
}

int itemListTCP()	{
	int i = 0;
	while(wp_buffer[i] != NULL){
		i++;
	}
	return i;
}

int existListTCP(u_int8_t *ether_shost,uint32_t ip_src)	{
	int exist = 0, i = 0,r;
	while(wp_buffer[i] != NULL)	{
		if(memcmp(ether_shost,wp_buffer[i]->ether_shost,8) == 0 && ip_src == wp_buffer[i]-> ip_src){
			exist = 1;
		}
		i++;	
	}
	if(exist == 1){
		r = i -1;
	}
	else{
		r = -1;
	}
	return r;
}

void printListTCP(int item)	{
	int i = item;
	printf("%s\t%s\n",toHWAddress(wp_buffer[i]->ether_shost),ip_format(wp_buffer[i]-> ip_src));
}



void memdump(unsigned char *memoria,int length)	{
	int i,j = 0;
	while(j <= (int)(length/16))	{
		printf(" %.8X:  ",(unsigned int)(memoria+(j*16)));
		i = 0;
		while(i < 16)	{
			if(((j*16)+ i) < length)
				printf(" %.2X",memoria[(j*16)+ i]);
			else
				printf(" XX");
			i++;
		}
		printf("  ");
		i = 0;
		while(i < 16)	{
			if(((j*16)+ i) < length)
				if(memoria[(j*16)+ i] >= 32 && memoria[(j*16)+ i]<=126)
					printf("%c",memoria[(j*16)+ i]);
				else
					printf(".");
			i++;
		}

		printf("\n");
		j++;
	}
}


int memsearch(unsigned char *memoria, unsigned char *str, int lenmem, int lenstr)	{
	int i= 0;
	int entrar = 1;
	while(i < lenmem -lenstr && entrar)	{
		if(memcmp((unsigned *)(memoria+i),str,lenstr) == 0) 	{
			entrar = 0;
		}
		i++;
	}
	if(entrar == 0)	{
		i = i -1;
	}
	else	{
		i = -1;
	}
	return i;
}




/*
 * =====================================================================================
*
 *       Filename:  tcputil.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/02/2013 07:17:02 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "tcputil.h"

void tcp_ntoh(tcphdr *header){

	header->sourceport = ntohs(header->sourceport);
	header->destport = ntohs(header->destport);
	header->seqnum = ntohl(header->seqnum);
	header->ack_seq = ntohl(header->ack_seq);
	header->orf = ntohs(header->orf);
	header->adwindow = ntohs(header->adwindow);
	
}


void tcp_hton(tcphdr *header){

	header->sourceport = htons(header->sourceport);
	header->destport = htons(header->destport);
	header->seqnum = (uint32_t)htonl(header->seqnum);
	header->ack_seq = (uint32_t)htonl(header->ack_seq);
	header->orf = (uint16_t)htons(header->orf);
	header->adwindow = (uint16_t)htons(header->adwindow);
	
}

//CONTAINS MALLOC
tcphdr *tcp_mastercrafter(uint16_t srcport, uint16_t destport,
			uint32_t seqnum, uint32_t acknum,
			bool fin, bool syn, bool rst, bool psh, bool ack,
			uint16_t adwindow){

	struct tcphdr *header = malloc(sizeof(struct tcphdr));

	if (header == NULL) {
		printf("\tERROR : Malloc failed\n");
		return NULL;
	}

	memset(header, 0, sizeof(struct tcphdr));

	header->sourceport = srcport;
	header->destport = destport;
	header->seqnum = seqnum;
	header->ack_seq = acknum;

	HDRLEN_SET(header->orf);
	if(fin) FIN_SET(header->orf);
	if(syn) SYN_SET(header->orf);
	if(rst) RST_SET(header->orf);
	if(psh) PSH_SET(header->orf);
	if(ack) ACK_SET(header->orf);
	header->adwindow = adwindow;	
	header->check = ZERO;

	return header;
}


int tcp_checksum(void *packet, uint16_t total_length) {
  
	uint32_t sum = 0;
	uint16_t odd_byte = 0;

	uint16_t *pseudo_itr = packet;
	int n = total_length;

  	while (n > 1) {
   	 	sum += *pseudo_itr++;
   	 	n -= 2;
 	}
 	//odd bytes
  	if (n == 1) {
    	*(uint8_t *)(&odd_byte) = *(uint8_t*)pseudo_itr;
   	 	sum += odd_byte;
  	}
  	//free(pseudo_hdr);

  	sum = (sum >> 16) + (sum & 0xffff); 
  	sum += (sum >> 16); 
  	uint16_t res;
  	res = ~sum;                
  	return res;
}



void tcp_print_packet_byte_ordered(tcphdr *header){

	printf("\nNETWORK BYTE ORDERED TCP HEADER---------------\n");
	printf("sourceport %u\n", ntohs(header->sourceport));
	printf("destport %u\n", ntohs(header->destport));
	printf("seqnum %lu\n", ntohl(header->seqnum));
	printf("ack_seq %lu\n", ntohl(header->ack_seq));
	printf("data offset: %d\n", ntohs(header->orf & 0xf000)>>12);
	printf("res: %d\n", (header->orf &0xFC0)>>6);
	printf("flags: \n");
	printf("	URG? %d\n", (header->orf & 0x20)>>5);
	printf("	ACK? %d\n", (header->orf & 0x10)>>4);
	printf("	PSH? %d\n", (header->orf & 0x08)>>3);
	printf("	RST? %d\n", (header->orf & 0x04)>>2);
	printf("	SYN? %d\n", (header->orf & 0x02)>>1);
	printf("	FIN? %d\n", (header->orf & 0x01));
	printf("adwindow: %u\n", ntohs(header->adwindow));
	printf("check: %x\n", header->check);
	//printf("urgptr: %u\n",header->urgptr);
	printf("------------------------\n\n");
}

void tcp_print_packet(tcphdr *header){
	printf("\nTCP HEADER---------------\n");
	printf("sourceport %u\n", header->sourceport);
	printf("destport %u\n", header->destport);
	printf("seqnum %lu\n", header->seqnum);
	printf("ack_seq %lu\n", header->ack_seq);
	printf("data offset: %d\n", (header->orf & 0xf000)>>12);
	printf("res: %d\n", (header->orf &0xFC0)>>6);
	printf("flags: \n");
	printf("	URG? %d\n", (header->orf & 0x20)>>5);
	printf("	ACK? %d\n", (header->orf & 0x10)>>4);
	printf("	PSH? %d\n", (header->orf & 0x08)>>3);
	printf("	RST? %d\n", (header->orf & 0x04)>>2);
	printf("	SYN? %d\n", (header->orf & 0x02)>>1);
	printf("	FIN? %d\n", (header->orf & 0x01));
	printf("adwindow: %u\n", header->adwindow);
	printf("check: %x\n", header->check);
	//printf("urgptr: %u\n",header->urgptr);
	printf("------------------------\n\n");
}





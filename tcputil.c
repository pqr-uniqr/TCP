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
	header->check = ntohs(header->check);
	//header->urgptr= ntohs(header->urgptr);
}


void tcp_hton(tcphdr *header){
	header->sourceport = htons(header->sourceport);
	header->destport = htons(header->destport);
	header->seqnum = htonl(header->seqnum);
	header->ack_seq = htonl(header->ack_seq);
	header->orf = htons(header->orf);
	header->adwindow = htons(header->adwindow);
	header->check = htons(header->check);
	//header->urgptr= htons(header->urgptr);
}


//CONTAINS MALLOC
tcphdr *tcp_mastercrafter(uint16_t srcport, uint16_t destport,
			uint32_t seqnum, uint32_t acknum,
			bool fin, bool syn, bool rst, bool psh, bool ack,
			uint16_t adwindow){
	struct tcphdr *header = malloc(sizeof(struct tcphdr));
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
	return header;
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
	printf("check: %u\n", header->check);
	//printf("urgptr: %u\n",header->urgptr);
	printf("------------------------\n\n");
}





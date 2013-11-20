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
	//header->check = ntohs(header->check); //mani commented out
	//header->urgptr= ntohs(header->urgptr);
}


void tcp_hton(tcphdr *header){

	header->sourceport = htons(header->sourceport);
	header->destport = htons(header->destport);
	header->seqnum = (uint32_t)htonl(header->seqnum);
	header->ack_seq = (uint32_t)htonl(header->ack_seq);
	header->orf = (uint16_t)htons(header->orf);
	header->adwindow = (uint16_t)htons(header->adwindow);
	//header->check = htons(header->check); //mani commented out
	//header->urgptr= htons(header->urgptr);
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
	header->adwindow = WINDOW_SIZE;	
	header->check = ZERO;

	return header;
}


void tcp_add_checksum(void *packet, uint16_t total_length, uint32_t src_ip, uint32_t dest_ip, uint16_t protocol) {

	(((struct tcphdr *)packet)->check) = 0;

	uint16_t checksum = tcp_checksum(packet, total_length, src_ip, dest_ip, protocol);

	(((struct tcphdr *)packet)->check) = checksum;
}	


int tcp_checksum(void *packet, uint16_t total_length, uint32_t src_ip, uint32_t dest_ip, uint16_t protocol) {
  

	uint32_t sum = 0;
	uint16_t odd_byte = 0;

	
	uint16_t *pseudo_hdr = (uint16_t *)malloc(total_length+12);

	if (pseudo_hdr == NULL) {
		printf("\t ERROR : malloc failed\n");
		return 0;
	}
	memset(pseudo_hdr, 0, total_length+12);
	
	((uint32_t *)pseudo_hdr)[0] = src_ip;
	((uint32_t *)pseudo_hdr)[1] = dest_ip;
	((uint8_t *)pseudo_hdr)[9] = (uint8_t)TCP;
	((uint16_t *)pseudo_hdr)[5] = ntohs((uint16_t)total_length);

	memcpy(((char *)pseudo_hdr)+12, packet, total_length);

	int n = total_length+12;
	uint16_t *pseudo_itr = pseudo_hdr;

  	while (n > 1) {
   	 	sum += *pseudo_itr++;
   	 	n -= 2;
 	}

    /* mop up an odd byte, if necessary */
  	if (n == 1) {
    	*(uint8_t *)(&odd_byte) = *(uint8_t*)pseudo_itr;
   	 	sum += odd_byte;
  	}
  	free(pseudo_hdr);

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





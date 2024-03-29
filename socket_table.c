/*
 * =====================================================================================
 *
 *       Filename:  connection_table.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/02/2013 07:18:27 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "socket_table.h"

struct pseudo_tcp
{
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	struct tcphdr tcp;
	char payload[MSS];

};

struct {
	const char *name;
} state_names[] = {
	{"LISTENING"},
	{"SYN_SENT"},
	{"SYN_RCVD"},
	{"ESTABLISHED"},
	{"FIN_WAIT_1"},
	{"CLOSE_WAIT"},
	{"FIN_WAIT_2"},
	{"LAST_ACK"},
	{"TIME_WAIT"},
	{"CLOSED"},
	{"CLOSING"},
	{"CLOSE"},
};

socket_t *fd_lookup(int fdnumber){

	socket_t *sock = NULL;
	HASH_FIND(hh1, fd_list, &fdnumber, sizeof(int), sock);
	return sock;
}


/* problem. added a new function which specifically check if there 
is a listening socket on our side (mani)*/


sockets_on_port *get_sockets_on_port(uint16_t port){

	sockets_on_port *sop = NULL;
	HASH_FIND(hh, sockets_by_port, &port, sizeof(uint16_t), sop);

	if(sop == NULL){
		//printf("sop for port %d not created yet\n", port);
		sop = malloc(sizeof(sockets_on_port));
		list_t *list = malloc(sizeof(list_t));
		list_init(&list);	
		sop->port = port;
		HASH_ADD(hh, sockets_by_port, port, sizeof(uint16_t), sop);
		sop->list = list;
		sop->listening_socket = NULL;
		//sop->socketcount = 0;
	}
	return sop;
}

int *is_listening(uint16_t port) {

	sockets_on_port *sop;
	HASH_FIND(hh, sockets_by_port, &port, sizeof(uint16_t), sop);
	return (sop == NULL) ? 0 : -1;
}


//TODO : receive window size should be 65535 not 0 when established
void print_sockets() {

	socket_t *sock, *temp;
	//printf("\nSOCKETS----------------------------------------------\n");
	printf("\nSockets:\n");

	if (HASH_CNT(hh1,fd_list) == 0) {
		printf("There are no socktes currently\n");
		return;
	}
	HASH_ITER(hh1, fd_list, sock, temp){
		print_socket(sock);
	}
	//printf("-----------------------------------------------------\n\n");
}

void print_socket(socket_t *s){

	char me[INET_ADDRSTRLEN];
	char her[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &s->myaddr, me, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &s->uraddr, her, INET_ADDRSTRLEN);
	
	if (s->state == LISTENING) {

		printf("\tid: %d - state: %s, receive window: %d, send window: 0\n", 
			s->id, state_names[s->state].name, WINSIZE);
		return;

	}
	
	printf("\tid: %d - state: %s, receive window: %d, send window: %d\n", 
			s->id, state_names[s->state].name, CB_GETCAP(s->recvw->buf),CB_GETCAP(s->sendw->buf));
	//printf("SOCKET ID: %d \nconnection{ %s (this node) (port: %d)\n <--%s--> (port: %d) %s }\n", s->id,me,s->myport,state_names[s->state].name,s->urport,her);
	//printf("		(at seqnum %d) 		(at seqnum %d)\n",s->myseq,s->ackseq);
}

void set_socketstate(socket_t *so, int state){

	int prevstate = so->state;
	so->state = state;
	if(state == SYN_SENT || state == SYN_RCVD){
		expect = 1;
	}


#ifdef DEBUG
	printf(_BRED_"SOCKET %d: %s -> %s\n"_NORMAL_, so->id, state_names[prevstate].name, state_names[so->state].name);
#endif
}

void socket_flush(socket_t *so){

	sendw_t *sendw = so->sendw;
	uint32_t tosend;
	int sent = 0;
	struct timeval senttime;

	//while(!CB_EMPTY(sendw->buf)){
		
	//read and send data
	tosend = MIN(MSS-TCPHDRSIZE-IPHDRSIZE, CB_SIZE(sendw->buf));
	//data
	unsigned char *payload = malloc(tosend);  //1360
	//copy data from CB to payload
	CB_READ(sendw->buf, payload, tosend);
	char *tcppacket = malloc(TCPHDRSIZE+tosend); //1360 + 20 = 1380
	memset(tcppacket, 0, TCPHDRSIZE+tosend); 
	//fill up the packet
	encapsulate_intcp(so, payload, tosend, tcppacket, so->myseq);
	sent += send_tcp(so, tcppacket, tosend+TCPHDRSIZE);
	gettimeofday(&senttime, NULL);
	#ifdef DEBUG
	printf("buffer flushed: %d bytes sent\n", sent-IPHDRSIZE-TCPHDRSIZE);
	#endif

	//store transmitted segment in retransmission queue with timestamp
	seg_t *el = malloc(sizeof(seg_t));
	memcpy(&el->lastsent, &senttime, sizeof(struct timeval));
	DL_APPEND(sendw->retrans_q_head, el);
	el->seqnum = so->myseq;
	el->seglen = tosend;
	el->data = payload;
	el->retrans_count = 0;

	if(el->seqnum == 1){
		gettimeofday(&span, NULL);
	}
	so->myseq = (so->myseq + tosend) % MAXSEQ; //TODO wrap
	free(tcppacket);
		//free(tcppacket);

	//}	

	
}

//for making data packet
void encapsulate_intcp(socket_t *so, void *data, int datasize, char *packet, uint32_t seqnum){

	//printf("seqnum at encapsulate_inip %d\n", seqnum);
	tcphdr *header = tcp_mastercrafter(so->myport, so->urport,
			seqnum, so->ackseq,
			0,0,0,0,1,
			CB_GETCAP(so->recvw->buf)-so->recvw->oor_q_size);

	if (header == NULL) {
		printf("\tWARNING : Could not make TCP header\n");
		return;
	}

	struct pseudo_tcp *p_tcp = (uint16_t *)malloc(sizeof(struct pseudo_tcp));
	memset(p_tcp, 0x0, sizeof(struct pseudo_tcp));

	//2. fill the header
	tcp_hton(header);
	memcpy(&p_tcp->tcp, header, TCPHDRSIZE);

	//1. fill the pseudiheader part
	((uint32_t *)p_tcp)[0] = so->myaddr;
	((uint32_t *)p_tcp)[1] = so->uraddr;
	((uint8_t *)p_tcp)[9] = (uint8_t)TCP;
	((uint16_t *)p_tcp)[5] = ntohs((uint16_t)TCPHDRSIZE+(uint16_t)datasize);

	//3. data
	memcpy(p_tcp->payload, data, datasize);

	//4. checksum
	uint16_t checksum = tcp_checksum(p_tcp, TCPHDRSIZE + datasize + 12);
  	header->check = checksum;

	if (header->check == 0) {
		printf("\t ERROR : something went wrong with checksum\n");
		header->check = 0xffffff;
	}

	//5. fill TCP part
	memcpy(packet, header, TCPHDRSIZE);
	memcpy(packet+TCPHDRSIZE, data, datasize);
	free(p_tcp);
	free(header);
	return;
}
//recvfile f ilename port
//sendfile ../testfiles/flights.csv 10.10.168.73 3
//recvfile

int send_tcp(socket_t *so, char *tcppacket, int size){
	interface_t *nexthop = get_nexthop(so->uraddr);
	char *packet = malloc(IPHDRSIZE + size); 
	encapsulate_inip(so->myaddr, so->uraddr, (uint8_t)TCP, (void *) tcppacket, size, &packet);
	int ret = send_ip(nexthop, packet, IPHDRSIZE+size);
	free(packet);
	return ret;
}

tcphdr *tcp_craft_ack(socket_t *so){
	return tcp_mastercrafter(so->myport, so->urport,
		so->myseq,so->ackseq,
		0,0,0,0,1,
		CB_GETCAP(so->recvw->buf)-so->recvw->oor_q_size);
}

void *buf_mgmt(void *arg){
	
	int s=(int)arg;
	socket_t *so = fd_lookup(s);
	sendw_t *sendw = so->sendw;
	int unsent_bytes, unacked_segs;
	seg_t *elt, *temp;
	struct timeval nowt, last_probe;
	gettimeofday(&last_probe, NULL);

	while(1){
		//if 2< seconds have passed with adwindow of 0, probe it (approximate)
		unsent_bytes = CB_SIZE(sendw->buf);
		DL_COUNT(sendw->retrans_q_head, elt, unacked_segs);
		//uint16_t fwind = so->sendw->adwindow;

		//TODO quick hack to prevent premature transfer
		if(so->state!=ESTABLISHED){
			continue;
		}

		//ANYTHING UNACKED?
		if(unacked_segs){
			//fwind -= sendw->retrans_q_head->seglen;
		
			//ANYTHING NEWLY ACKED?
			pthread_mutex_lock(&sendw->lock);
			DL_FOREACH_SAFE(sendw->retrans_q_head,elt,temp){
				//stop here
				if(elt->seqnum == sendw->hack) break; 

				uint32_t seqnum = elt->seqnum;
				uint32_t acknum = seqnum + elt->seglen;
				ack_t *ack;

				//look for ack in ackhistory
				HASH_FIND(hh, sendw->ackhistory, &acknum, sizeof(uint32_t), ack);
				double samplertt = 0;
				if(ack!=NULL && !elt->retrans_count){
					double lastsent = elt->lastsent.tv_sec + (elt->lastsent.tv_usec/1000000.0);
					double acked_at = ack->tstamp.tv_sec + (ack->tstamp.tv_usec/1000000.0);
					samplertt = acked_at - lastsent;
					sendw->srtt = sendw->srtt * ALPHA + samplertt * (1-ALPHA);
					sendw->rto = MIN(RTO_UBOUND, MAX(RTO_LBOUND, BETA * sendw->srtt));
					HASH_DEL(sendw->ackhistory, ack);
					free(ack);
				}

				#ifdef DEBUG
				printf("\nSEGMENT ACKNOWLEDGED-----------------------\n");
				printf(_GREEN_"*segment [%d ---%d bytes--- %d] \n"_NORMAL_,elt->seqnum, elt->seglen,
							(elt->seqnum+elt->seglen-1) %MAXSEQ);
				printf("acked in %f seconds (transmitted %d times)\n", samplertt, 
					elt->retrans_count+1);
				printf("(rto updated to %f)\n", sendw->rto);
				char *data = elt->data;
				printf("----------------------------\n");
				#endif

				/*  
				if(elt->seqnum > 1047550){
					double start = span.tv_sec + span.tv_usec /1000000.0;
					gettimeofday(&span,NULL);
					double end = span.tv_sec + span.tv_usec / 1000000.0;
					printf("total span was %f\n", end-start);
				} */

				DL_DELETE(sendw->retrans_q_head, elt);
				int seglen = elt->seglen;
				free(elt->data);
				free(elt);
				if(seqnum + seglen == sendw->hack) break;
			}

			//ANYTHING TIMED OUT? ONLY THE HEAD VERSION
			seg_t *head = sendw->retrans_q_head;
			if(head){
				gettimeofday(&nowt, NULL);
				double now = nowt.tv_sec + (nowt.tv_usec/1000000.0);
				double then = head->lastsent.tv_sec +
					(head->lastsent.tv_usec/1000000.0);
				if(now - then > sendw->rto){
					#ifdef DEBUG
					printf(_RED_"RETRANSMITTING:\n"_NORMAL_);
					printf(_RED_"	segment [%d ---%d bytes--- %d]\n"_NORMAL_, head->seqnum, head->seglen,
						head->seqnum + head->seglen -1);
					#endif

					head->retrans_count++;
					char *tcppacket = malloc(TCPHDRSIZE+head->seglen);
					encapsulate_intcp(so,head->data,head->seglen,tcppacket,head->seqnum);
					send_tcp(so,tcppacket,head->seglen+TCPHDRSIZE);
					free(tcppacket);
					gettimeofday(&head->lastsent, NULL);
				}
			}
			pthread_mutex_unlock(&sendw->lock);

			/* BATCH RETRANSMISSION VERSION
			DL_FOREACH(sendw->retrans_q_head, elt){
				gettimeofday(&nowt, NULL);
				double now = nowt.tv_sec + (nowt.tv_usec/1000000.0);
				double then = elt->lastsent.tv_sec + (elt->lastsent.tv_usec/1000000.0);
				if(now - then > TIMEOUT){
					elt->retrans_count++;
					char *tcppacket = malloc(TCPHDRSIZE+ elt->seglen);
					encapsulate_intcp(so, elt->data, elt->seglen, tcppacket, elt->seqnum);
					send_tcp(so, tcppacket, elt->seglen + TCPHDRSIZE);
					gettimeofday(&elt->lastsent, NULL);
				}
			} */
		}

		//there's unsent data -- should we flush them?
		if(unsent_bytes && unacked_segs < 10){
			//if((unsent_bytes >=MSS) && (fwind >= MSS)){
			if(unsent_bytes >= MSS){
				socket_flush(so);
			} else if(!unacked_segs){
				socket_flush(so);
			}
		}
	}
}



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

struct {
	const char *name;
} state_names[] = {
	{"LISTENING"},
	{"SYN_SENT"},
	{"SYN_RCVD"},
	{"ESTABLISHED"}
};

socket_t *fd_lookup(int fdnumber){
	socket_t *sock;
	HASH_FIND(hh1, fd_list, &fdnumber, sizeof(int), sock);
	return sock;
}

sockets_on_port *get_sockets_on_port(uint16_t port){
	sockets_on_port *sop;
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

/*
int destroy_socket(int socket){
	//find the socket
	socket_t *so = fd_lookup(socket);
	printf("so found\n");
	HASH_DELETE(hh1, fd_list, so);
	HASH_DELETE(hh2, socket_table, so);

	
	socket_t *s, *tmp;
	HASH_ITER(hh1, fd_list, s,tmp){
		if(so->id == s->id) HASH_DEL(fd_list, s);
	}
	HASH_ITER(hh2, socket_table, s, tmp){
		if(so->id == s->id) HASH_DEL(fd_list, s);
	}
	sockets_on_port *sop = get_sockets_on_port(so->myport);
	printf("sop search\n"); */
	//if(sop->listening_socket->id==so->id) sop->listening_socket = NULL;
	//TODO above applies only to when destroying a passive socket 
	/*
	node_t curr;
	for(curr=sop->list->head;curr!=NULL;curr=curr->next){
		socket_t *s = curr->data;
		if( ((socket_t *)curr->data)->id == so->id){
			curr->data = NULL;
		}
	} 
	printf("free?\n");
	free(so);

}
*/
void print_sockets(){
	socket_t *sock, *temp;
	HASH_ITER(hh1, fd_list, sock, temp){
		print_socket(sock);
	}
}

void print_socket(socket_t *s){
	char me[INET_ADDRSTRLEN];
	char her[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &s->myaddr, me, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &s->uraddr, her, INET_ADDRSTRLEN);

	printf("SOCKET ID: %d \nconnection{%s (this node) (port: %d)\n <--%s--> (port: %d) %s }\n", s->id,me,s->myport,state_names[s->state].name,s->urport,her);
	printf("		(at seqnum %d) 		(at seqnum %d)\n",s->myseq,s->ackseq);
}

void set_socketstate(socket_t *so, int state){

	int prevstate = so->state;
	so->state = state;
	if(state == SYN_SENT || state == SYN_RCVD){
		expect = 1;
	}

	printf("SOCKET %d: %s -> %s\n", so->id, state_names[prevstate].name, state_names[so->state].name);
}

void socket_flush(socket_t *so){
	sendw_t *sendw = so->sendw;
	int tosend;
	int sent = 0;

	while(!CB_EMPTY(sendw->buf)){

		//read and send data
		tosend = MIN(MSS-TCPHDRSIZE-IPHDRSIZE, CB_SIZE(sendw->buf));
		unsigned char *payload = malloc(tosend);
		CB_READ(sendw->buf, payload, tosend);
		char *tcppacket = malloc(TCPHDRSIZE+tosend);
		encapsulate_intcp(so, payload, tosend, tcppacket, so->myseq);
		sent += send_tcp(so, tcppacket, tosend+TCPHDRSIZE);

		//store transmitted segment in retransmission queue with timestamp
		retrans_t *el = malloc(sizeof(retrans_t));
		el->seqnum = so->myseq;
		el->seglen = tosend;
		gettimeofday(&el->lastsent, NULL);
		el->data = payload;
		el->retrans_count = 0;
		DL_APPEND(sendw->retrans_q_head, el);

		//update myseq and potentially wrap around
		so->myseq = (so->myseq + tosend) % MAXSEQ;
		free(tcppacket);
	}	

#ifdef DEBUG
	printf("buffer flushed: %d bytes sent\n", sent);
#endif

}


int send_tcp(socket_t *so, char *tcppacket, int size){
	interface_t *nexthop = get_nexthop(so->uraddr);
	char *packet = malloc(IPHDRSIZE + size);
	encapsulate_inip(so->myaddr, so->uraddr, (uint8_t)TCP, (void *) tcppacket, size, &packet);
	return send_ip(nexthop, packet, IPHDRSIZE+size);
}

tcphdr *tcp_craft_ack(socket_t *so){
	return tcp_mastercrafter(so->myport, so->urport,
		so->myseq,so->ackseq,
		0,0,0,0,1,
		so->adwindow);
}


//for making data packet
void encapsulate_intcp(socket_t *so, void *data, int datasize, char *packet, uint32_t seqnum){
	
	tcphdr *header = tcp_mastercrafter(so->myport, so->urport,
			seqnum, so->ackseq,
			0,0,0,0,1,
			so->adwindow);
	tcp_hton(header);
	memcpy(packet, header, TCPHDRSIZE);
	memcpy(packet+TCPHDRSIZE, data, datasize);
	return;
}


void buf_mgmt(void *arg){
	int s=(int)arg;
	socket_t *so = fd_lookup(s);
	sendw_t *sendw = so->sendw;
	int unsent_bytes, unacked_segs;
	retrans_t *elt, *temp;
	struct timeval nowt;

	while(1){
		if(!so->adwindow)	continue; //receiver window closed--probe
		//TODO lock the window
		unsent_bytes = CB_SIZE(sendw->buf);
		DL_COUNT(sendw->retrans_q_head,elt,unacked_segs);
		//unacked_bytes = (so->myseq-1)- sendw->lba;

		//there's unacked bytes -- should we retransmit them?
		if(unacked_segs){
			DL_FOREACH(sendw->retrans_q_head, elt){
				gettimeofday(&nowt);
				double now = nowt.tv_sec + (nowt.tv_usec/1000000.0);
				double then = elt->lastsent.tv_sec + (elt->lastsent.tv_usec/1000000.0);
				if(now - then > TIMEOUT){
					elt->retrans_count++;
					char *tcppacket = malloc(TCPHDRSIZE+ elt->seglen);
					encapsulate_intcp(so, elt->data, elt->seglen, tcppacket, elt->seqnum);
					send_tcp(so, tcppacket, elt->seglen + TCPHDRSIZE);
					gettimeofday(&elt->lastsent, NULL);
				}
			}
		}

		//there's unsent data -- should we flush them?
		if(unsent_bytes){
			//effective window size
			uint32_t fwind = so->adwindow - (so->myseq - sendw->retrans_q_head-seqnum);
			if((unsent_bytes >=MSS) && (fwind >= MSS)){
				socket_flush(so);
			}

			if(!unacked_segs && (fwind >= unsent_bytes)){
				socket_flush(so);
			}
		}
	}
}









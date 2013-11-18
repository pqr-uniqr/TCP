/*
 * =====================================================================================
 *
 *       Filename:  v_api.c
 *
 *    Description:  UNIX-like Transport layer API function calls
 *
 *        Version:  1.0
 *        Created:  11/05/2013 02:25:43 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#define SIMPLESEQ //start with Sequence number 0 --easier to debug
#include "v_api.h"

int v_socket(){
	socket_t *so = malloc(sizeof(socket_t));
	if(so == NULL) return -1; //"malloc failed"
	memset(so,0,sizeof(socket_t));
	so->id = maxsockfd++;
	so->q= malloc(sizeof(bqueue_t));

	bqueue_init(so->q);
	HASH_ADD(hh1, fd_list, id, sizeof(int), so);
	return so->id;
}

int v_bind(int socket, struct in_addr *addr, uint16_t port){
	//find the socket, set port, add it to its port list
	socket_t *so = fd_lookup(socket);
	if(so==NULL) return -1; //"no such socket"
	so->myport = port;
	sockets_on_port *sop = get_sockets_on_port(port);
	list_append(sop->list, so);
	return 0;
}

int v_listen(int socket){
	socket_t *so = fd_lookup(socket);
	if(so==NULL) return -1; //"no such socket"
	sockets_on_port *sop = get_sockets_on_port(so->myport);
	if(sop->listening_socket) return -1; //"already listening on this port"
	sop->listening_socket = so;
	set_socketstate(so,LISTENING);
	return 0;
}


int v_accept(int socket, struct in_addr *node){
	socket_t *nso, *lso = fd_lookup(socket); //nso -> new socket, lso -> listening socket
	struct in_addr anyaddr;
	anyaddr.s_addr = 0;
	if(lso->state != LISTENING) return -1; //"this is not a listening socket"

	//get the request
	void *request;
	DQ(lso->q, &request);

	//make an active socket for this connection
	int s = v_socket();
	v_bind(s, &anyaddr, lso->myport);
	nso = fd_lookup(s);
	memcpy(&(nso->uraddr), request+TCPHDRSIZE, SIZE32);
	memcpy(&(nso->myaddr), request+TCPHDRSIZE+SIZE32, SIZE32);
	nso->urport = ((tcphdr *)request)->sourceport;
	nso->ackseq= ++(((tcphdr *)request)->seqnum); 
	nso->myseq = rand() % MAXSEQ;
	#ifdef SIMPLESEQ
	nso->myseq = 0;
	#endif
	set_socketstate(nso, SYN_RCVD);
	nso->adwindow = ((tcphdr*)request)->adwindow;
	init_windows(nso);

	//initiate buffer mamagement
	pthread_t mgmt_thr;
	pthread_attr_t thr_attr;
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&mgmt_thr, &thr_attr, buf_mgmt ,(void *) s);

	//add to socket_table
	HASH_ADD(hh2, socket_table, urport, keylen, nso);
	free(request);

	//if caller wants request origin
	if(node!=NULL) node->s_addr = nso->uraddr;

	//send respones (second grip)
	tcp_send_handshake(2, nso);
	return s;
}



int v_connect(int socket, struct in_addr *addr, uint16_t port){
	//bind the socket to a random port
	struct in_addr any_addr;
	any_addr.s_addr = 0;
	int bind_ret = v_bind(socket, &any_addr, rand()%MAXPORT);
	if(bind_ret == -1) return -1; //something went wrong at v_bind (no socket, not valid pnum)
	socket_t *so = fd_lookup(socket);

	//populate socket with info	
	so->urport = port;
	so->uraddr = addr->s_addr;
	//my addr is the interface IP address we will be sending request out to
	interface_t *i = get_nexthop(so->uraddr);
	so->myaddr = i->sourcevip;
	so->myseq = rand() % MAXSEQ;
	#ifdef SIMPLESEQ
	so->myseq = 0;
	#endif
	set_socketstate(so, SYN_SENT);
	init_windows(so);

	//commence buffer management
	int s = (int)socket;
	pthread_t mgmt_thr;
	pthread_attr_t thr_attr;
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&mgmt_thr, &thr_attr, buf_mgmt, (void *) s);

	//store it in the lookup table (urport, myport, uraddr)
	HASH_ADD(hh2, socket_table, urport, keylen, so);

	//send a connection request (first grip)
	tcp_send_handshake(1, so);
	return 0;
}


//malloc and initialize sending and receiving window
void init_windows(socket_t *so){
	so->sendw = malloc(sizeof(sendw_t));
	so->recvw = malloc(sizeof(recvw_t));
	CB_INIT(&so->sendw->buf, MAXSEQ/2);
	CB_INIT(&so->recvw->buf, MAXSEQ/2);
	//unsigned char *send_start = so->sendw->buf->write_pointer;
	unsigned char *recv_start = so->recvw->buf->write_pointer;
	//so->sendw->lbw = send_start; 
	//so->sendw->lbs = send_start;
	//so->sendw->lba = so->myseq;
	so->sendw->retrans_q_head = NULL;

	so->recvw->lbc = recv_start;
	so->recvw->nbe = recv_start + 1;
	so->recvw->lbr = recv_start;

	return;
}

int v_write(int socket, const unsigned char *buf, uint32_t nbyte){
	socket_t *so = fd_lookup(socket);
	if(so==NULL) return 0; //no such socket
	if(CB_FULL(so->sendw->buf)) return 0; //"no write possible"
	int cap = CB_GETCAP(so->sendw->buf);
	int ret = CB_WRITE(so->sendw->buf, buf, MIN(cap, nbyte));
	printf("%d written to the buffer\n", ret);
	return ret;
}


int v_read(int socket, unsigned char *buf, uint32_t nbyte){
	socket_t *so = fd_lookup(socket);
	if(so==NULL) return 0; //no such socket
	recvw_t *recvw = so->recvw;
	int toread = MIN(nbyte, CB_SIZE(recvw->buf));
	if(toread <= 0) return 0;
	printf("v_read\n");
	int ret = CB_READ(recvw->buf, buf, toread);
	recvw->lbr += toread;
	so->adwindow = CB_GETCAP(recvw->buf);
	return ret;
}


void tcp_send_handshake(int gripnum, socket_t *socket){
	tcphdr *header;
	switch(gripnum){
		case 0:
			//TODO RST
			header = tcp_mastercrafter(0, 0,
									0, 0,
									0,0,1,0,0,
									0);
			break;
		case 1 :
			//first grip of 3WH
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, 0,
									0,1,0,0,0,
									MAXSEQ/2); //half the max sequence number
			break;
		case 2 :
			//second of 3WH
			header =  tcp_mastercrafter(socket->myport, socket->urport,
									(socket->myseq)++, socket->ackseq,
									0,1,0,0,1,
									MAXSEQ/2);
			break;
		case 3 :
			//third of 3WH
			header =  tcp_mastercrafter(socket->myport, socket->urport,
									++(socket->myseq), socket->ackseq, 
									0,0,0,0,1,
									MAXSEQ/2);
	}
	//send the packet
	tcp_hton(header);
	interface_t *nexthop = get_nexthop(socket->uraddr);
	char *packet = malloc(IPHDRSIZE+TCPHDRSIZE);
	encapsulate_inip(socket->myaddr,socket->uraddr,(uint8_t)TCP,(void *)header, TCPHDRSIZE, &packet);
	send_ip(nexthop, packet, TCPHDRSIZE+IPHDRSIZE);
	return;

}


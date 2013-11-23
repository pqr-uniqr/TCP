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
#include "common.h"

int v_socket() {

	socket_t *so = malloc(sizeof(socket_t));

	if(so == NULL) {
		printf(" v_socket() error : malloc failed\n");
		return -1; 
	}

	memset(so,0,sizeof(socket_t));
	so->id = maxsockfd++;
	so->q= malloc(sizeof(bqueue_t));

	bqueue_init(so->q);
	HASH_ADD(hh1, fd_list, id, sizeof(int), so);

	so->read_lock = 0; //not read_locked initially mani
	

	return so->id;
}
 
int v_bind(int socket, struct in_addr *nothing, uint16_t port) {

	//find the socket, set port, add it to its port list
	socket_t *so = fd_lookup(socket);

	if(so == NULL) {
		printf(" v_bind() error : malloc failed\n");
		return -1; 
	}

	so->myport = port;
	sockets_on_port *sop = get_sockets_on_port(port);
	list_append(sop->list, so);

	return 0;

}

int v_listen(int socket){

	socket_t *so = fd_lookup(socket);
	if(so == NULL) {
		printf(" v_listen() error : malloc failed\n");
		return -1; 
	}
	sockets_on_port *sop = get_sockets_on_port(so->myport);

	if(sop->listening_socket) return -1; //"already listening on this port"

	sop->listening_socket = so;
	so->state = LISTENING;

	return 0;

}






int v_connect(int socket, struct in_addr *addr, uint16_t port){

#ifdef DEBUG
	printf(" v_connect() Trying to connect\n");
#endif

	//bind the socket to a random port
	int ret;
	struct in_addr any_addr;
	any_addr.s_addr = 0;

	ret = v_bind(socket, &any_addr, rand()%MAXPORT);

	//something went wrong at v_bind (no socket, not valid pnum)
	if(ret < 0) {	
#ifdef DEBUG
	printf(" v_connect() error : v_bind() failed\n");
#endif
		
		return -1; 

	}

#ifdef DEBUG
	printf(" v_connect() : v_bind() success\n");
#endif

	socket_t *so = fd_lookup(socket);
	if (so == NULL) {

#ifdef DEBUG
		printf(" v_connect() error : fd_lookup() failed\n");
#endif
		so->state = CLOSE;
		return -1;
	}

#ifdef DEBUG
	printf(" v_connect() : fd_lookup() success\n");
#endif
	
	//store it in the lookup table (urport, myport, uraddr) + init windows
	init_windows(so);	
	
	//populate socket with info	
	so->urport = port;
	so->uraddr = addr->s_addr;
	//my addr is the interface IP address we will be sending request out to
	interface_t *i = get_nexthop(so->uraddr);
	if (i == NULL) {
		so->state = CLOSE;
		return -EHOSTUNREACH;
	}

	so->myaddr = i->sourcevip;
	so->myseq = rand() % MAXSEQ;

#ifdef DEBUG
	printf(" v_connect() : so->* success\n");
#endif

#ifdef DEBUG
			printf(" v_connect: Added socket %d to socket_table"_NORMAL_"\n", so->id);
#endif

	HASH_ADD(hh2, socket_table, urport, keylen, so);

	so->state = SYN_SENT;

#ifdef DEBUG
	printf(" v_connect() : socket %d moved into state SYN_SENT\n", so->id);
#endif

	tcp_send_handshake(1, so);
	
#ifdef DEBUG
			printf(_RED_" v_connect: send syn"_NORMAL_"\n");
			printf(_BLUE_" v_connect: timed out"_NORMAL_"\n");
#endif

	time_t now = time(NULL);
	time_t next = now;
	time_t diff = 0;
	int count = 0;

	//send a connection request (first grip)
	while ((count < MAX_SYN_REQ)) {

		if (so->state == ESTABLISHED) {
			break;
		}
		
		next = time(NULL);
		diff = next-now;

		if (diff == 1) {
			tcp_send_handshake(1, so);
			count++;

#ifdef DEBUG
			printf(_RED_" v_connect: send syn"_NORMAL_"\n");
			printf(_BLUE_" v_connect: timed out"_NORMAL_"\n");
#endif

			now = next;
		}
	}

	// Could not connect
	if (so->state == SYN_SENT || so->state == CLOSE) {
		so->state = CLOSED;
		return -ENOTCONN;
	}

	//commence buffer management
    int s = (int)socket;
    pthread_attr_t thr_attr;
    pthread_attr_init(&thr_attr);
    pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&so->th, &thr_attr, buf_mgmt, (void *) s);

	return 0;
}

int v_accept(int socket, struct in_addr *node){

	socket_t *lso = fd_lookup(socket); //lso -> listening socket

	socket_t *nso;//nso -> new socket
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
	//#ifdef SIMPLESEQ
	//nso->myseq = 0;
	//#endif

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

int v_write(int socket, const unsigned char *buf, uint32_t nbyte){

	socket_t *so = fd_lookup(socket);

	if((so == NULL) || (so->state == CLOSE)) {

#ifdef DEBUG
		printf(_RED_"v_connect: Connection does not exists for socket %d "_NORMAL_"\n", so->id);
#endif
		return -1;
	}

	/************** My write is shut down ***************/
	if (so->state == FIN_WAIT_2) {

#ifdef DEBUG
		printf(_RED_"v_connect: connection closing for socket %d "_NORMAL_"\n", so->id);
#endif
		return -EPIPE;
	}
	
	if (so->state == CLOSED) {

#ifdef DEBUG
		printf(_RED_"v_connect: connection closing for socket %d "_NORMAL_"\n", so->id);
#endif
		return -EBADF;
	}


	if(CB_FULL(so->sendw->buf)) return 0; //"no write possible"
	int cap = CB_GETCAP(so->sendw->buf);
	int ret = CB_WRITE(so->sendw->buf, buf, MIN(cap, nbyte));
	printf("%d written to the buffer\n", ret);
	return ret;

}

//malloc and initialize sending and receiving window
void init_windows(socket_t *so) {

	so->sendw = malloc(sizeof(sendw_t));
	so->recvw = malloc(sizeof(recvw_t));
	CB_INIT(&so->sendw->buf, WINSIZE);
	CB_INIT(&so->recvw->buf, WINSIZE);
	//unsigned char *send_start = so->sendw->buf->write_pointer;
	//unsigned char *recv_start = so->recvw->buf->write_pointer;
	//so->sendw->lbw = send_start; 
	//so->sendw->lbs = send_start;
	//so->sendw->lba = so->myseq;
	so->sendw->retrans_q_head = NULL;
	so->sendw->acked = 1; //TODO make this work for non SIMPLESEQ case
	so->recvw->oor_q_head = NULL;
	return;

}

/**
* TODO : take the pseudo header function out. NOTE : make sure it is generic
* enough to be called by handshake funcs AND send data funcs.
* TODO : 3rd shake might have data
* TODO : RST
*/
void tcp_send_handshake(int gripnum, socket_t *socket){

	tcphdr *header = NULL;

	switch(gripnum) {

		case 0:
			printf("\t TODO : RST NOT IMPLEMENTED YET\n");

		case SYN_SENT://1'st shake
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, 0,0,1,0,0,0,MAXSEQ); //half the max sequence number
			
			break;
		case SYN_RCVD://2'nd shake
			header = tcp_mastercrafter(socket->myport, socket->urport,
									(socket->myseq)++, socket->ackseq,
									0,1,0,0,1,MAXSEQ);

			break;

		case ESTABLISHED://3'rd shake
			header = tcp_mastercrafter(socket->myport, socket->urport,
									++(socket->myseq), socket->ackseq, 
									0,0,0,0,1,MAXSEQ);
			break;

		case FIN_WAIT_1:// from ESTABLISHED --> FIN_WAIT_1 state (FIN SEGMENT)
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, socket->ackseq, 
									1,0,0,0,1,MAXSEQ);
			break;

		case CLOSE_WAIT: //regular ACK
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, socket->ackseq, 
									0,0,0,0,1,MAXSEQ);
			break;

		case LAST_ACK: // moving from CLOSE_WAIT --> LAST_ACK (FIN SEGMENT)
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, socket->ackseq, 
									1,0,0,0,1,MAXSEQ);
			break;

		case CLOSING: // moving from FIN_WAIT_1 --> CLOSING
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, socket->ackseq, 
									1,0,0,0,1,MAXSEQ);
			break;

		case RST: // RST packet
			header = tcp_mastercrafter(socket->myport, socket->urport,
									socket->myseq, socket->ackseq, 
									1,0,0,0,1,MAXSEQ);
			break;

		default:
			printf("\t WARNING : Unknown shake!\n");
			return;
	}

	//0. make sure TCP header is not NULL
	if (header == NULL) {
		printf("\tWARNING : Could not make TCP header\n");
		return;
	}
	

	struct pseudo_tcpp *tcp_packet = (uint16_t *)malloc(sizeof(struct pseudo_tcpp));
	memset(tcp_packet, 0x0, sizeof(struct pseudo_tcpp));

	//1. fill the pseudiheader part
	((uint32_t *)tcp_packet)[0] = socket->myaddr;
	((uint32_t *)tcp_packet)[1] = socket->uraddr;
	((uint8_t *)tcp_packet)[9] = (uint8_t)TCP;
	((uint16_t *)tcp_packet)[5] = ntohs((uint16_t)TCPHDRSIZE);


	//2. fill the header 
	tcp_hton(header);
	memcpy(&tcp_packet->tcp, header, TCPHDRSIZE);

	//3. data (NONE)
	//TODO : 3rd handshake could have data. 
	memset(tcp_packet->payload, 0, 1024);

	//4. checksum
	uint16_t checksum = tcp_checksum(tcp_packet, TCPHDRSIZE+12);
	

	//5. set the checksum in the TCP header
	header->check = checksum;
	if (header->check == 0) {
		printf("\t ERROR : something went wrong with checksum\n");
		return;
	}

	//6. TODO : error checking
	interface_t *nexthop = get_nexthop(socket->uraddr);

	//TODO : packet top pass to ip
	char *packet = (char *)malloc(TCPHDRSIZE+IPHDRSIZE);

	if (packet == NULL) {
		printf("\t ERROR : Malloc failed\n");
		return;
	}

	//7. copy the TCP header to ip packet
	memset(packet, 0, TCPHDRSIZE+IPHDRSIZE);
	memcpy(packet, header, TCPHDRSIZE);

	//8. NO data, so you are done : pass to ip
	encapsulate_inip(socket->myaddr,socket->uraddr,(uint8_t)TCP,header, TCPHDRSIZE, &packet);

	//9. TCP/IP packet all set, sending time
	send_ip(nexthop, packet, TCPHDRSIZE+IPHDRSIZE);

	return;
}

int v_read(int socket, unsigned char *buf, uint32_t nbyte){

	socket_t *so = fd_lookup(socket);

	if(so==NULL) return 0; //no such socket

	recvw_t *recvw = so->recvw;

	int toread = MIN(nbyte, CB_SIZE(recvw->buf));

	if(toread <= 0) return 0;

	printf(_RED_"v_read\n");

	int ret = CB_READ(recvw->buf, buf, toread);

	/*
	Buffer gets empty by each read but the adwin is not reflecting the 
	real space left to peers
	*/
	if (so->read_lock == 1) { 
		printf(" v_read() data received -> %s\n", buf);
		memset(buf, 0, toread);
		int ret = CB_WRITE(recvw->buf, buf, toread);
		//printf("**** %d\n", so->adwindow);
		return -1;		
	}

	//printf("----- SIZE IS %d\n", so->adwindow);
	so->adwindow = CB_GETCAP(recvw->buf);
	return ret;

}
/*
1. shutdown read :
	a) added read_lock to sturct socket (bool)
	b) v_socket will initialize the read_lock to 0
	c) whenever v_shutdown is called with read_lock only, the followiing happens :
		i) set the read_lock = 1
		ii) When v_read() reads the data from the buffer, CB_WRIE nbytes (read) 0's 
		So the pointer is fine and adwin is shrinking constantly
*/
int v_shutdown(socket_t *socket, int shut_type) {

	printf("IN SHUTDOWN\n");

	//1. get the socket by id
	socket_t *so = fd_lookup(socket);
	if(so == NULL) return 0; //no such socket

	if (shut_type == SHUTDOWN_READ) {
		
		printf("\t Request for shutdown read\n");
		so->read_lock = 1; 

	}
	/******************* CLOSING RECIVING WINDOW ***************
	* Send FIN
	* 1. if current state == Established
	*	-> change to FIN_WAIT_1
	* 2. if current state == CLOSE_WAIT (peer already closed down)
	*	-> change to LAST_ACK
	***********************************************************/
	else if (shut_type == SHUTDOWN_WRITE) {
		
		printf("\t Request for shutdown write\n");
		if (so->state == ESTABLISHED) {

			so->state = FIN_WAIT_1;	
			tcp_send_handshake(FIN_WAIT_1, so);

		}
		else if (so->state == CLOSE_WAIT) {
			so->state = LAST_ACK;
			tcp_send_handshake(LAST_ACK, so);
		}
		
		
	}
	else if (shut_type == SHUTDOWN_BOTH) {

		printf("Request for shutdown read and write\n");		
		v_shutdown(so->id, SHUTDOWN_READ);
		v_shutdown(so->id, SHUTDOWN_WRITE);

	}
	return 0;
}

/******************** v_cose() ********************************
transmit all the packets not yet ransmitted, then close the connection
***************************************************************/
int v_close(int socket) {

	socket_t *so = fd_lookup(socket);
	
	if(so == NULL) {
#ifdef DEBUG
		printf(_RED_"v_close: socket %d does not exist"_NORMAL_"\n", socket);
#endif
		return -EBADF;
	}

#ifdef DEBUG
		printf(_BLUE_"v_close: shutting down both read and write on socket %d "_NORMAL_"\n", socket);
#endif

	v_shutdown(socket, SHUTDOWN_BOTH);

	pthread_cancel(so->th);

	HASH_DELETE(hh1, fd_list, so);

	return 0;

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
	printf("sop search\n"); 
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
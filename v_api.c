/*
 * =====================================================================================
 *
 *       Filename:  v_api.c
 *
 *    Description:  v_* type UNIX-like Transport layer API function calls
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

#include "v_api.h"

int v_socket(){
	socket_t *so = malloc(sizeof(socket_t));
	if(so == NULL) return -1; //"malloc failed"
	memset(so,0,sizeof(socket_t));
	so->id = maxsockfd++;
	so->q = malloc(sizeof(bqueue_t));
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
	nso->urseq = ((tcphdr *)request)->seqnum; //leave increments to sending funcs
	nso->myseq = rand() %MAXSEQ;
	set_socketstate(nso, SYN_RCVD);

	HASH_ADD(hh2, socket_table, urport, keylen, nso);
	free(request);

	//if caller wants request origin
	if(node!=NULL) node->s_addr = nso->uraddr;

	//send respones (second grip)
	tcphdr *second_grip = tcp_craft_handshake(2, nso);
	tcp_hton(second_grip);
	//TODO calculate checksum
	int ret = v_write(s, (unsigned char *) second_grip, TCPHDRSIZE);
	if(ret == -1) return -1; //"v_write failed"
	free(second_grip);

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
	set_socketstate(so, SYN_SENT);

	//store it in the lookup table (urport, myport, uraddr)
	HASH_ADD(hh2, socket_table, urport, keylen, so);

	//send a connection request (first grip)
	struct tcphdr *first_grip = tcp_craft_handshake(1, so);
	tcp_hton(first_grip);
	//TODO claculate checksum
	int write_ret = v_write(socket, (unsigned char *)first_grip, TCPHDRSIZE);
	free(first_grip);
	if(write_ret == -1) return -1; //"v_write failed"
	return 0;
}


int v_write(int socket, const unsigned char *buf, uint32_t nbyte){
	//MTU check (might be redundant)
	if(nbyte+IPHDRSIZE > MTU) return -1;

	//get nexthop
	socket_t *so = fd_lookup(socket);
	interface_t *nexthop = get_nexthop(so->uraddr);

	//put in ip and send it
	char *packet = malloc(nbyte+IPHDRSIZE);
	encapsulate_inip(so->myaddr, so->uraddr, TCP, (void *) buf, nbyte, &packet);
	return send_ip(nexthop, packet, nbyte+IPHDRSIZE);
}





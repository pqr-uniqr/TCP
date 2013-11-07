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

int destroy_socket(int socket){
	//find the socket
	socket_t *so = fd_lookup(socket);
	printf("so found\n");
	HASH_DELETE(hh1, fd_list, so);
	HASH_DELETE(hh2, socket_table, so);

	/*  
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
	} */
	printf("free?\n");
	free(so);

}

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
	printf("		(at seqnum %d) 		(at seqnum %d)\n",s->myseq,s->urseq);
}

void set_socketstate(socket_t *so, int state){
	int prevstate = so->state;
	so->state = state;
	if(state == SYN_SENT || state == SYN_RCVD){
		expect = 1;
	}

	printf("SOCKET %d: %s -> %s\n", so->id, state_names[prevstate].name, state_names[so->state].name);
}










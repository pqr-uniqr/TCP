#include "common.h"
#include "srwindow.h"



typedef struct socket{
	//lookup key for handle hh1
	int id;

	//the following three form a lookup key for handle hh2
	uint16_t urport;
	uint16_t myport;
	uint32_t uraddr;

	uint32_t myaddr;
	uint32_t myseq;
	uint32_t ackseq;

	bqueue_t *q;
	sendw_t *sendw;
	recvw_t *recvw;

	//state representation 
	int state;

	UT_hash_handle hh1; //hashed by id (fd number)
	UT_hash_handle hh2; //hashed by compound key {urport,myport,uraddr} --order matters
	
} socket_t;


typedef struct sockets_on_port{
	uint16_t port;
	list_t *list;
	socket_t *listening_socket;

	UT_hash_handle hh; //hashed by port
} sockets_on_port;


typedef struct socket_lookup_key{ 
	uint16_t urport;
	uint16_t myport;	
	uint32_t uraddr;
} socket_lookup_key;



extern socket_t *fd_list; //hash table (id, socket)
extern socket_t *socket_table; //hash table ({urport, myport, uraddr}, socket)
extern sockets_on_port *sockets_by_port;
extern int maxsockfd;
extern unsigned keylen;
extern int expect;


socket_t *fd_lookup(int fdnumber);
sockets_on_port *get_sockets_on_port(uint16_t port);
void print_sockets();
void print_socket(socket_t *sock);
void set_socketstate(socket_t *so, int state);
void socket_flush(socket_t *so);
int send_tcp(socket_t *so, char *tcppacket, int size);
tcphdr *tcp_craft_ack(socket_t *so);
void encapsulate_intcp(socket_t *so, void *data, int datasize, char *packet, uint32_t seqnum);
void *buf_mgmt(void *arg);

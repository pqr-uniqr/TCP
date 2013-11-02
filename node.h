#include "csupport/list.c"
#include "csupport/parselinks.c"
#include "csupport/ipsum.c"
#include "csupport/colordefs.h"
#include "csupport/uthash.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <mcheck.h>
#include <signal.h>



//node.h defines the MACROS
#define INFINITY 	16
#define MAX_ROUTES	64
#define HOP_COST	1

#define NEIGHBOUR	0
#define ANONYMOUS	1

#define RECVBUFSIZE 	65536
#define CMDBUFSIZE 	1024
#define MAXIDENT	10

#define LOCALDELIVERY 	1
#define FORWARD 	0

#define UP 		1
#define DOWN 		0
#define OWN_COST	0
#define REQUEST 	1
#define RESPONSE	2
#define MTU		1400

#define LOCAL		1

#define IPHDRSIZE sizeof(struct iphdr)

#define IP 0
#define RIP 200

#define REFRESH_TIME	15

typedef struct interface_t interface_t;
typedef struct interface_t 			interface_t;
typedef struct rtu_routing_entry 	rtu_routing_entry;
typedef struct rip_entry 	rip_entry;
typedef struct rip_packet 	rip_packet;





//interface- with this file included,
//you can set up interfaces, put them down and up
struct interface_t{
	int id;
	int sockfd;
	struct sockaddr *sourceaddr;
	struct sockaddr *destaddr;
	uint32_t sourcevip;
	uint32_t destvip;
	bool status;

	int mtu;
};
int setup_interface(char *filename);
void up_interface(int id);
void down_interface(int id);
int send_ip(interface_t *inf, char *packet, int packetsize);
int get_socket (uint16_t portnum, struct addrinfo **source, int type);
int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local);


//ip_packet- with this file included,
//you can pack ip packets and unpack them to make sense of them
int encapsulate_inip(uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet);
int id_ip_packet(char *packet, struct iphdr **ipheader);



//routing-
//with this file included,
//you can initiate a routing table
//manage a routing table
//pack an RIP packet based on the current routing table
//consult the RIP packet
struct rip_entry {
	uint32_t cost;
	uint32_t addr;
};

struct rip_packet {
	uint16_t command;
	uint16_t num_entries;
	rip_entry entries[];
};

struct rtu_routing_entry {
	uint32_t addr;
	uint32_t cost;
	uint32_t nexthop;
	int local;
	time_t ttl;
	
	UT_hash_handle hh;
};

int rt_init();
int rt_add(uint32_t nexthop, uint32_t destVip, int cost, int local);
rip_packet *rip_response_packet(uint32_t dest, int *totsize);
interface_t *rt_get_nexthop(uint32_t dest_vip);
int rt_update(rip_packet *table, uint32_t inf_from);
void routing_table_send_update();


//utility- with this file included
//you can print shit
void print_interfaces();
void print_help();
void print_routes();


//uint32_t route_lookup(uint32_t final_dest); DEPRECATED
//rtu_routing_entry *find_route_entry(uint32_t id); DEPRECATED
//int routing_table_send_request(interface_t *port); DEPRECATED
//int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr, int type); DEPRECATED



#include "csupport/list.h"
#include "csupport/parselinks.h"
#include "csupport/ipsum.h"
#include "csupport/colordefs.h"
#include "csupport/uthash.h"
#include "csupport/bqueue.h"
#include "csupport/circular_buffer.h"
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
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
#define SIZE32	sizeof(uint32_t)

#define IP 0
#define RIP 200
#define TCP 6

#define REFRESH_TIME	15

//TCP macros
#define MAXPORT 65535 
#define MAXSEQ 65535 
#define NQ bqueue_enqueue
#define DQ bqueue_dequeue
#define CBT circular_buffer_t
#define CB_INIT circular_buffer_init

//TCP state machine macros
#define LISTENING 0
#define SYN_SENT 1
#define SYN_RCVD 2
#define ESTABLISHED 3




//uint32_t route_lookup(uint32_t final_dest); DEPRECATED
//rtu_routing_entry *find_route_entry(uint32_t id); DEPRECATED
//int routing_table_send_request(interface_t *port); DEPRECATED
//int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr, int type); DEPRECATED



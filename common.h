#include "csupport/list.h"
#include "csupport/parselinks.h"
#include "csupport/ipsum.h"
#include "csupport/colordefs.h"
#include "csupport/uthash.h"
#include "csupport/utlist.h"
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
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <mcheck.h>
#include <signal.h>


#define DEBUG

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
#define TIMEOUT 5 //timeout macro for TCP retransmission

//TCP macros
#define MSS 1400
#define MAXPORT 65535 
#define MAXSEQ (unsigned) (65535 * 2)
#define WINSIZE 100
#define NQ bqueue_enqueue
#define DQ bqueue_dequeue
#define CBT circular_buffer_t
#define CB_INIT circular_buffer_init
#define CB_GETCAP circular_buffer_get_available_capacity
#define CB_FULL circular_buffer_is_full
#define CB_WRITE circular_buffer_write
#define CB_READ circular_buffer_read
#define CB_EMPTY circular_buffer_is_empty
#define CB_SIZE circular_buffer_get_size
#define MIN(a,b) a>b? b:a
//TCP state machine macros
#define LISTENING 0
#define SYN_SENT 1
#define SYN_RCVD 2
#define ESTABLISHED 3




//uint32_t route_lookup(uint32_t final_dest); DEPRECATED
//rtu_routing_entry *find_route_entry(uint32_t id); DEPRECATED
//int routing_table_send_request(interface_t *port); DEPRECATED
//int routing_table_update(rip_packet *table, uint32_t src_addr, uint32_t dest_addr, int type); DEPRECATED



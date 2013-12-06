#include "csupport/list.h"
#include "csupport/parselinks.h"
#include "csupport/ipsum.h"
#include "csupport/colordefs.h"
#include "csupport/uthash.h"
#include "csupport/utlist.h"
#include "csupport/bqueue.h"
#include "csupport/circular_buffer.h"
#include <limits.h>
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
#include <pthread.h>

//#define DEBUG
#define SIMPLESEQ //start with Sequence number 0 --easier to debug

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

#define WINDOW_SIZE 65535 //mani
#define ZERO 0 //mani
#define TCP_PSEUDO_HDR_SIZE 12

#define MSS 1400
#define MAXSEQ (unsigned) 4294967295 //2^32 -1
#define WINSIZE 65535
/*  
#define MSS 45
#define MAXSEQ (unsigned) 20
#define WINSIZE 10 */


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

#define ALPHA (double) 0.8
#define BETA (double) 1.5
#define RTO_UBOUND 120
#define RTO_LBOUND (double) 0.005
#define TIMEOUT (double) 0.005 //timeout macro for TCP retransmission
//#define MIN(X,Y) ((X) < (Y) ? : (X) : (Y))
#define MIN(a,b) a > b? b:a
#define MAX(a,b) a > b? a:b
//TCP state machine macros



#define LISTENING 		0
#define SYN_SENT 		1
#define SYN_RCVD 		2
#define ESTABLISHED 	3
#define FIN_WAIT_1 		4

#define CLOSE_WAIT		5
#define FIN_WAIT_2		6
#define LAST_ACK		7
#define TIME_WAIT		8
#define CLOSED			9
#define CLOSING			10
#define CLOSE			11

#define ACKNOWLEDGE		5
#define RST 			11
#define MAX_SYN_REQ		3
//mani
#define LINE_MAX 50
#define FILE_BUF_SIZE	1024

#define SHUTDOWN_READ	0
#define SHUTDOWN_WRITE	1
#define SHUTDOWN_BOTH	2



/************************** TCP ERROR CODES ************************/
#define ENOTCONN        107
#define EHOSTUNREACH    113     /* No route to host */
#define EPIPE           32      /* Broken pipe */

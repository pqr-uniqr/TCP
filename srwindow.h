#include "common.h"
#include "tcputil.h"


typedef struct retransmission_segment{
	void *data;
	uint32_t seqnum;
	uint32_t seglen;
	int retrans_count;
	struct timeval lastsent;
	//for UTLIST
	struct retransmission_segment *next, *prev;
} retrans_t;


typedef struct sending_window{
	CBT *buf;
	retrans_t *retrans_q_head;
	pthread_mutex_t lock; //TODO use mutex
} sendw_t;


typedef struct receiving_window{
	CBT *buf;
	unsigned char *lbc;
	unsigned char *nbe;
	unsigned char *lbr;
	pthread_mutex_t lock;
} recvw_t;



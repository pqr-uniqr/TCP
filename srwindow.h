#include "common.h"
#include "tcputil.h"


typedef struct segment{
	void *data;
	uint32_t seqnum;
	uint32_t seglen;
	int retrans_count;
	struct timeval lastsent;
	//for UTLIST
	struct segment *next, *prev;
} seg_t;

typedef struct sending_window{
	CBT *buf;
	seg_t *retrans_q_head;
	uint32_t acked;
	struct timeval acked_at;
	pthread_mutex_t lock; //TODO use mutex
} sendw_t;

typedef struct receiving_window{
	CBT *buf;
	seg_t *oor_q_head;
	pthread_mutex_t lock;
} recvw_t;


#include "common.h"
#include "tcputil.h"


typedef struct acknowledgement{
	uint32_t ackseq; //key
	struct timeval tstamp;
	UT_hash_handle hh; //hashable
} ack_t;

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

	uint32_t hack;
	ack_t *ackhistory; //hash table for acknowledgement history
	double srtt;
	double rto;
	uint16_t adwindow; //adwindow of the corresponding receiving window
	
	pthread_mutex_t lock; 
} sendw_t;

typedef struct receiving_window{
	CBT *buf;
	seg_t *oor_q_head;
	uint16_t oor_q_size;
	pthread_mutex_t lock;
} recvw_t;


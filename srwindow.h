#include "common.h"
#include "tcputil.h"

typedef struct sending_window{
	CBT *buf;
	unsigned char *lbw;
	unsigned char *lbs;
	unsigned char *lba;
	pthread_mutex_t lock;
} sendw_t;

typedef struct receiving_window{
	CBT *buf;
	unsigned char *lbc;
	unsigned char *nbe;
	unsigned char *lbr;
	pthread_mutex_t lock;
} recvw_t;



#include "common.h"
#include "interface.h"

typedef struct tcphdr{
	uint16_t sourceport;
	uint16_t destport;
	uint32_t seqnum;
	uint32_t ack_seq;
	uint16_t orf;
	uint16_t adwindow;
	uint16_t check;
	uint16_t urggptr;
} tcphdr;

//macros for tcputil.c -
#define TCPHDRSIZE sizeof(struct tcphdr)
#define HDRLEN(orf) ((0xf000)>>12)
#define URG(orf) ((0x20 & orf) >>5)
#define ACK(orf) ((0x10 & orf) >>4)
#define PSH(orf) ((0x08 & orf) >>3)
#define RST(orf) ((0x04 & orf) >>2)
#define SYN(orf) ((0x02 & orf) >>1)
#define FIN(orf) ((0x01 & orf))
#define HDRLEN_SET(orf) (orf |= 0x5000)
#define URG_SET(orf) (orf |= 0x20)
#define ACK_SET(orf) (orf |= 0x10)
#define PSH_SET(orf) (orf |= 0x08)
#define RST_SET(orf) (orf |= 0x04)
#define SYN_SET(orf) (orf |= 0x02)
#define FIN_SET(orf) (orf |= 0x01)



//takes in pointer to the start of the TCP packet, populates res
//int decapsulate_fromtcp(char *packet, struct tcphdr *res);

void tcp_hton(tcphdr *header);
void tcp_ntoh(tcphdr *header);
tcphdr *tcp_mastercrafter(uint16_t srcport, uint16_t destport,
			uint32_t seqnum, uint32_t acknum,
			bool fin, bool syn, bool rst, bool psh, bool ack,
			uint16_t adwindow);
void tcp_print_packet(tcphdr *header);

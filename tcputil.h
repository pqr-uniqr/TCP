#include <netinet/tcp.h>


//TODO takes in pointer to the start of the TCP packet, populates res
int decapsulate_fromtcp(char *packet, struct tcphdr *res);

//TODO tcphdr to network byte order
void tcp_hton(struct tcphdr *header)
//TODO tcphdr to host byte order
void tcp_ntoh(struct tcphdr *header)

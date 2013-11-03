#include "ip_common.h"
#include "rip.h"
#include "iputil.h"


extern list_t *interfaces;
extern int maxfd;
extern fd_set masterfds;
extern rtu_routing_entry *routing_table;

//interface- with this file included,
//you can set up interfaces, put them down and up
typedef struct interface_t interface_t;
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
int get_socket (uint16_t portnum, struct addrinfo **source, int type);
int get_addr(uint16_t portnum, struct addrinfo **addr, int type);
int send_ip(interface_t *inf, char *packet, int packetsize);
int id_address(uint32_t destaddr);


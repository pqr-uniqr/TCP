#include "common.h"
#include "tcputil.h"

int v_socket();
int v_bind(int socket, struct in_addr *addr, uint16_t port);
int v_listen(int socket);
int v_accept(int socket, struct in_addr *node);
int v_connect(int socket, struct in_addr *addr, uint16_t port);
int v_write(int socket, const unsigned char *buf, uint32_t nbyte);

#include "common.h"
#include "socket_table.h"

int v_socket();
int v_bind(int socket, struct in_addr *nothing, uint16_t port);
int v_listen(int socket);
int v_accept(int socket, struct in_addr *node);
int v_connect(int socket, struct in_addr *addr, uint16_t port);
int v_write(int socket, const unsigned char *buf, uint32_t nbyte);
int v_read(int socket, unsigned char *buf, uint32_t nbyte);
int v_shutdown(socket_t *socket, int shut_type);

void tcp_send_handshake(int gripnum, socket_t *socket);
void init_windows(socket_t *so);
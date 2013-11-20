#include "v_api.h"

void rip_handler(const char *packet, interface_t *inf, int nothing2);
void ip_handler(const char *packet, interface_t *nothing, int received_bytes);
void tcp_handler(const char *packet, interface_t *nothing, int nothing2);

void decrement_ttl();
void regular_update();

int rt_init(); //TODO this can be incorporated into interface.
void broadcast_rip_table();
void *recv_thr_func(void *nothing);

void print_interfaces();
void print_routes();
void print_help();

//cmd functions (subset-ed to TCP specific commands)
void accept_cmd(const char *line);
void connect_cmd(const char *line);
void send_cmd(const char *line);
void recv_cmd(const char *line);

void test_checksum(const char *line);

int v_read_all(int s, void *buf, size_t bytes_requested);
/*  
void sendfile_cmd(const char *line);
void recvfile_cmd(const char *line);
void shutdown_cmd(const char *line);
void close_cmd(const char *line); */

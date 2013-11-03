#include "interface.h"


void rip_handler(const char *, interface_t *inf, int received_bytes);
void ip_handler(const char *, interface_t *inf, int received_bytes);
void tcp_handler(const char *, interface_t *inf, int received_bytes);

void decrement_ttl();
void regular_update(int *timer);
int rt_init();
void broadcast_rip_table();
interface_t *get_nexthop(uint32_t dest_vip);
void print_interfaces();
void print_routes();
void print_help();

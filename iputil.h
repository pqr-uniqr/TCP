#include "ip_common.h"

extern list_t *interfaces;

int encapsulate_inip(uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet);
uint32_t decapsulate_fromip(char *packet, struct iphdr **ipheader);

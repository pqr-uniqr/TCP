#include "ip_common.h"

//routing-
//with this file included,
//you can initiate a routing table
//manage a routing table
//pack an RIP packet based on the current routing table
//consult the RIP packet
typedef struct rtu_routing_entry 	rtu_routing_entry;
typedef struct rip_entry 	rip_entry;
typedef struct rip_packet 	rip_packet;

extern rtu_routing_entry *routing_table;

struct rip_entry {
	uint32_t cost;
	uint32_t addr;
};

struct rip_packet {
	uint16_t command;
	uint16_t num_entries;
	rip_entry entries[];
};

struct rtu_routing_entry {
	uint32_t addr;
	uint32_t cost;
	uint32_t nexthop;
	int local;
	time_t ttl;
	
	UT_hash_handle hh;
};

int rt_add(uint32_t nexthop, uint32_t destVip, int cost, int local);
rip_packet *rip_response_packet(uint32_t dest, int *totsize);
int rt_update(rip_packet *table, uint32_t inf_from);

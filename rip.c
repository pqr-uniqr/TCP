/*
 * =====================================================================================
 *
 *       Filename:  rip.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/02/2013 01:46:40 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "rip.h"


//add entry to routing table
int rt_add(uint32_t nexthop, uint32_t destVip, int cost, int local) {
	rtu_routing_entry *new;

	HASH_FIND(hh, routing_table, &destVip, sizeof(uint32_t), new);

	if (new == NULL) {
		new = (rtu_routing_entry *)malloc(sizeof(rtu_routing_entry));

		if (new == NULL) {
			printf("ERROR : Malloc new routing entry failed\n");
			return -1;
		}

		//where does this lead to?
		new->addr = destVip;	
		HASH_ADD(hh, routing_table, addr, sizeof(uint32_t), new);
		new->cost = cost;
		new->nexthop = nexthop;
		new->local = local;
		new->ttl = REFRESH_TIME;
	}

	else {
		//printf("\troute: Refreshing entry for %s, cost still %d\n", dest, new->cost);
		new->ttl = REFRESH_TIME;
	}

	return 0;
}



//make and return an RIP response packet
rip_packet *rip_response_packet(uint32_t dest, int *totsize) {

	rip_packet *packet;
	int num_routes = HASH_COUNT(routing_table);
	int size = sizeof(rip_packet) + sizeof(rip_entry)*num_routes;


	packet = (rip_packet *)malloc(size);
	if (packet == NULL) {
		perror("Route response");
		exit(1);
	}

	packet->command = htons((uint16_t)RESPONSE);
	packet->num_entries = htons((uint16_t)num_routes);


	int index = 0;
	rtu_routing_entry *info, *tmp;
	uint32_t cost;

	HASH_ITER(hh, routing_table, info, tmp) {

		//split the hotizon with poison reverse
		if (dest == info->nexthop && info->cost != 0) {
			cost = INFINITY;
		} else {
			cost = info->cost;
		}

		//cost = info->cost;
		packet->entries[index].addr = info->addr;
		packet->entries[index].cost = htonl(cost);

		index++;
	}	
	*totsize = size;
	return packet;
}



//this function puts the RIP table received and the address of the sender to make reasonable updates to the table
//inf_otherend is the sender of the update
int rt_update(rip_packet *table, uint32_t inf_otherend) {

	int i, trigger = 0;
	uint32_t address, cost;
	rtu_routing_entry *myroute, *tmp;
	list_t *credible_entries;
	node_t *curr;

	list_init(&credible_entries);

	//Find routes that pass through whoever we just received the table from
	HASH_ITER(hh, routing_table, myroute, tmp){
		if(inf_otherend == myroute->nexthop){
			uint32_t *cred= malloc(sizeof(uint32_t));
			memcpy(cred, &myroute->addr, sizeof(uint32_t));
			list_append(credible_entries, cred);
		}
	}

	//If this is a previously unkown destination, add it to the table
	for(i=0;i<ntohs(table->num_entries);i++){
		address = table->entries[i].addr;
		cost = ntohl(table->entries[i].cost);
		HASH_FIND(hh,routing_table,&address, sizeof(uint32_t),myroute);

		if(myroute==NULL){
			rt_add(inf_otherend, address, cost+HOP_COST, 0);
			trigger=1;
			continue;
		}
	}

	HASH_ITER(hh, routing_table, myroute, tmp){
		for(i=0;i<ntohs(table->num_entries);i++){
			address = table->entries[i].addr;
			cost=ntohl(table->entries[i].cost);

			//refresh routes that pass through this sender
			if(myroute->nexthop == inf_otherend){
				myroute->ttl = REFRESH_TIME;
			}

			//found a better path through a new hop
			if(myroute->nexthop != inf_otherend && myroute->addr == address && !myroute->local && cost+HOP_COST < myroute->cost){
				myroute->nexthop = inf_otherend;
				myroute->cost = cost + HOP_COST;
				myroute->ttl = REFRESH_TIME;
				trigger = 1;

			} else {
				for(curr=credible_entries->head;curr!=NULL;curr=curr->next){
					uint32_t *credible = (uint32_t *)curr->data;
					//for routes that pass through the sender, find the matching entries in the received table and update cost
					if(address == *credible && myroute->addr == address){
						if(cost == INFINITY){
							if(myroute->cost != INFINITY){
								trigger = 1;
								myroute->ttl = 15;
							}
							myroute->cost = INFINITY;
						}else if (myroute->cost != cost+HOP_COST){
							myroute->cost = cost+HOP_COST;
							myroute->ttl = 15;
							trigger=1;
						}
					}
				}
			}

		}
	}

	/*  
	if(trigger){
		//print_routes();
		routing_table_send_update();
	} */

	for(curr = credible_entries->head;curr!=NULL;curr=curr->next){
		free((uint32_t *)curr->data);
	}
	list_free(&credible_entries);

	return trigger;
}


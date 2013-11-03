#include "node.h"

int maxfd;
list_t  *interfaces, *routes;


struct {
	int protocol;
	void (*handler)(const char *, interface_t *, int);
} protocol_handlers[] = {
	{RIP, rip_handler},
	{IP, ip_handler},
	{TCP,tcp_handler}
};


int main ( int argc, char *argv[]) {

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}

	struct timeval tv, tvcopy;
	char readbuf[CMDBUFSIZE], recvbuf[RECVBUFSIZE];
	char *token;
	char *delim = " ";
	int read_bytes, received_bytes, myident = 1;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	struct iphdr *ipheader;
	interface_t *i;
	rip_packet *rip;
	node_t *curr;
	int updateTimer= 9;

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_ZERO(&masterfds);
	FD_SET(0, &masterfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	maxfd = 2;
	if(setup_interface(argv[1]) == -1){
		printf("ERROR : setup_interface failed\n");
		exit(1);
	}

	if (rt_init() == -1) {
		printf("ERROR : init_routing failed\n");
		exit(1);
	}

	while(1){

		regular_update(&updateTimer);
		decrement_ttl();
		readfds = masterfds;
		tvcopy = tv;

		if(select(maxfd+1, &readfds, NULL, NULL, &tvcopy) == -1){
			perror("select()");
			exit(1);
		}

		for(curr = interfaces->head;curr!=NULL;curr=curr->next){

			i = (interface_t *)curr->data;

			if(FD_ISSET(i->sockfd, &readfds)){

				if ((received_bytes = recvfrom(i->sockfd, recvbuf, RECVBUFSIZE, 0, &sender_addr, &addrlen)) == -1) {
					perror("recvfrom()");
					exit(1);
				}

				//don't take gifts from strangers
				if(i->status==DOWN){continue;}

				ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
				uint32_t destaddr = decapsulate_fromip(recvbuf, &ipheader);

				//it's for me!
				if(id_address(destaddr)){
					unsigned j;
					for(j=0;j<sizeof(protocol_handlers) /sizeof(protocol_handlers[0]);j++){
						if(ipheader->protocol == protocol_handlers[j].protocol){
							protocol_handlers[j].handler(recvbuf, i, received_bytes);
						}
					}
				}
				//packet to be forwarded
				else {
					interface_t *inf;
					inf = get_nexthop(ipheader->daddr);
					char *packet = malloc(received_bytes);
					memcpy(packet, recvbuf, received_bytes);
					send_ip(inf, packet, received_bytes);
					free(packet);
				}

				free(ipheader);
			}
		}

		//command line parsing
		if(FD_ISSET(0, &readfds)){
			memset(readbuf, 0,CMDBUFSIZE);
			read_bytes = read(0, readbuf, CMDBUFSIZE);

			if(read_bytes == -1){
				perror("read()");
				exit(-1);
			}

			readbuf[read_bytes-1] = '\0';

			char *data; //pointer for the string part of the input
			if((token =strtok_r(readbuf, delim, &data)) ==NULL){print_help();continue;}





			//+++++++++++++++++++++++++++++++++++++++++++++++++++
			//----------------IP related CMDs--------------------
			//+++++++++++++++++++++++++++++++++++++++++++++++++++

			if(!strcmp("send", token)){
				struct in_addr destaddr;
				interface_t *inf;

				//get VIP of destination and look up next hop and its interface
				if ((token = strtok_r(NULL,delim, &data)) == NULL){ print_help(); continue;}

				inet_pton(AF_INET, token, &destaddr);
				inf = get_nexthop(destaddr.s_addr);

				//get the protocol and pointer to the data
				if((token = strtok_r(NULL, delim, &data))==NULL){ print_help(); continue;}

				//send the last packet
				char *packet = malloc(IPHDRSIZE + strlen(data));
				int packetsize = encapsulate_inip(inf->sourcevip, destaddr.s_addr, atoi(token), data, strlen(data),&packet);
				send_ip(inf, packet, packetsize);
				free(packet);
				myident++;
			}

			if(!strcmp("up",token)){
				if((token = strtok_r(NULL, delim, &data)) == NULL){ print_help(); continue;}
				up_interface(atoi(token));
				broadcast_rip_table();
			}
			if(!strcmp("down",token)){
				if((token = strtok_r(NULL, delim, &data)) == NULL){ print_help(); continue;}
				down_interface(atoi(token));
				broadcast_rip_table();

			}
			if(!strcmp("routes", token)){
				print_routes();
			}
			if(!strcmp("interfaces", token)){
				print_interfaces();
			}
			if(!strcmp("quit", readbuf)){
				break;
			}
		}
	}

	printf("safe exiting\n");

	//clean up memory before exiting
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *i = (interface_t *)curr->data;
		close(i->sockfd);
		free(i->sourceaddr);
		free(i->destaddr);
		free(i);
	}

	list_free(&interfaces);

	rtu_routing_entry *entry, *temp;
	HASH_ITER(hh, routing_table, entry, temp){
		HASH_DEL(routing_table, entry);
		free(entry);
	}

	return EXIT_SUCCESS;
}



void rip_handler(const char *packet, interface_t *i, int received_bytes){
	int totsize;
	char *rippart = (char *)packet+IPHDRSIZE;
	rip_packet *rip = (rip_packet *)malloc(sizeof(rip_packet));
	memcpy(rip,rippart,sizeof(rip_packet));

	//it's an RIP request
	if(ntohs(rip->command) == REQUEST){
		rip_packet *pack = rip_response_packet(i->destvip, &totsize);
		char *packet = malloc(IPHDRSIZE + totsize);
		int packetsize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)RIP, pack, totsize, &packet);
		send_ip(i, packet, packetsize);
		free(pack);
		free(packet);
	}
	//it's an RIP response
	else if (ntohs(rip->command) == RESPONSE) {
		int size = sizeof(rip_packet) + sizeof(rip_entry)*ntohs(rip->num_entries);
		rip_packet *packet= (rip_packet *)malloc(size);
		memcpy(packet, rippart, size);
		if(rt_update(packet, i->destvip)){
			print_routes();
			broadcast_rip_table();
		}
		free(packet);
	}
	free(rip);
}

void ip_handler(const char *packet, interface_t *inf, int received_bytes){
	int payloadsize = received_bytes-IPHDRSIZE;
	char payload[payloadsize];
	memcpy(payload, packet+IPHDRSIZE, payloadsize);
	payload[payloadsize] = '\0';
	printf("%s\n", payload);
}


//initial branching of cases will happen here!
void tcp_handler(const char *packet, interface_t *inf, int received_bytes){
	printf("tcp_handler\n");
}



interface_t *get_nexthop(uint32_t dest_vip){
	rtu_routing_entry *entry;
	HASH_FIND(hh, routing_table, &dest_vip, sizeof(uint32_t), entry);

	if(entry == NULL){
		printf("Destination not found in routing table\n");
		return NULL;
	}

	node_t *curr;
	for(curr=interfaces->head; curr!=NULL; curr=curr->next){
		interface_t *inf = (interface_t *) curr->data;
		if(inf->destvip == entry->nexthop){
			return inf;
		}
	}
	printf("Interface not found for this nexthop address\n");
	return NULL;
}




//send routing table out to everyone
void broadcast_rip_table() {
	node_t *curr;
	interface_t *i;
	rip_packet *pack;
	char *packet;
	int maSize, totsize;

	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		i = (interface_t *)curr->data;
		if(i->status==DOWN){
			continue;
		}

		pack = rip_response_packet(i->destvip, &totsize);
		packet = malloc(IPHDRSIZE + totsize);
		maSize = encapsulate_inip(i->sourcevip, i->destvip, (uint8_t)200, pack, totsize, &packet);
		send_ip(i, packet, maSize);
		free(pack);
		free(packet);
	}
}

//initialize routing table
int rt_init() {

	routing_table = NULL;
	node_t *curr;

	for (curr = interfaces->head; curr != NULL; curr = curr->next) {
		interface_t *inf = (interface_t *)curr->data;
		if (rt_add(inf->sourcevip, inf->sourcevip, 0, 1) == -1) { //local
			printf("WARNING : Entry was NOT added to routing table!\n");
			continue;
		}
	}
	return 0;
}


void print_help(){
	printf("commands:\n\
		send vip protocol string\n\
		routes\n\
		interfaces\n\
		up int\n\
		down int\n\
		q\n\
		mtu int int\n");
}



//as name suggests
void print_interfaces () 
{
	node_t *curr;
	interface_t *inf;
	char src[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
	printf("Interfaces:\n");

	for(curr = interfaces->head;curr!=NULL;curr=curr->next){
		inf = (interface_t *)curr->data;
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->sourcevip)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(inf->destvip)), dest, INET_ADDRSTRLEN);
		printf("  %d: %s->%s. %s\n",inf->id, src, dest, (inf->status == UP) ? "UP" : "DOWN");
	}
}		

//as name suggests
void print_routes () 
{
	rtu_routing_entry *tmp;
	rtu_routing_entry *info;
	char src[INET_ADDRSTRLEN];
	char nexthop[INET_ADDRSTRLEN];

	printf("Routing table:\n");

	HASH_ITER(hh, routing_table, info, tmp) {

		inet_ntop(AF_INET, ((struct in_addr *)&(info->addr)), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ((struct in_addr *)&(info->nexthop)), nexthop, INET_ADDRSTRLEN);
		printf("  Route to %s with cost %d, %s (%s) ttl: %d\n",src, info->cost, (info->local == 1) ? "through self" : "remote", nexthop, (int)info->ttl);

	}

    printf(_NORMAL_);
}

void regular_update(int *updateTimer){
	if (++(*updateTimer)== 10) {
		*updateTimer = 0;
		broadcast_rip_table();
	}
}

void decrement_ttl(){
	rtu_routing_entry *entry, *temp;
	char xx[INET_ADDRSTRLEN];
	HASH_ITER(hh, routing_table, entry, temp){
		if(entry->cost != 0 && entry->ttl != 0){
			entry->ttl--;
			if(entry->ttl==0){
				inet_ntop(AF_INET, ((struct in_addr *)&(entry->addr)), xx, INET_ADDRSTRLEN);
				printf("entry to %s expired\n", xx);
				entry->cost = 16;
			}
		}
	}
}

#include "node.h"

int interface_count = 0, maxfd;
list_t  *interfaces, *routes;
fd_set masterfds;
rtu_routing_entry *routing_table;


int main ( int argc, char *argv[]) {

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}

	struct timeval tv, tvcopy;
	char readbuf[CMDBUFSIZE], recvbuf[RECVBUFSIZE];
	char *token, *rippart;
	char *delim = " ";
	int read_bytes, received_bytes, totsize, myident = 1;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	struct iphdr *ipheader;
	interface_t *i;
	rip_packet *rip;
	node_t *curr;
	int maTime = 9;

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

		if (++maTime == 10) {
			maTime = 0;
			routing_table_send_update();
		}

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
				if(i->status==DOWN){continue;}
				ipheader = (struct iphdr *)malloc(sizeof(struct iphdr));
				//if id_ip_packet() thinks this packet is for local delivery
				if(id_ip_packet(recvbuf,&ipheader) == LOCALDELIVERY){

					//this packet is an RIP packet
					if(ipheader->protocol == RIP){

						inet_ntop(AF_INET, ((struct in_addr *)&(ipheader->saddr)), xx, INET_ADDRSTRLEN);

						rippart = (char *)recvbuf+IPHDRSIZE;
						rip = (rip_packet *)malloc(sizeof(rip_packet));
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
							//printf("routing table from %s\n", xx);
							int size = sizeof(rip_packet) + sizeof(rip_entry)*ntohs(rip->num_entries);
							rip_packet *packet= (rip_packet *)malloc(size);
							memcpy(packet, rippart, size);
							rt_update(packet, i->destvip);
							free(packet);
						}
						free(rip);

					} else if (ipheader->protocol == IP){
						recvbuf[received_bytes] = '\0';
						char *payload = recvbuf+IPHDRSIZE;
						printf("%s\n", payload);
					}
				}

				//packet is to be forwarded
				else {
					interface_t *inf;

					inf = rt_get_nexthop(ipheader->daddr);

					char *packet = malloc(received_bytes);
					memcpy(packet, recvbuf, received_bytes);
					send_ip(inf, packet, received_bytes);
					free(packet);
				}

				free(ipheader);
			}
		}

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

			if(!strcmp("send", token)){
				struct in_addr destaddr;
				interface_t *inf;

				//get VIP of destination and look up next hop and its interface
				if ((token = strtok_r(NULL,delim, &data)) == NULL){ print_help(); continue;}

				inet_pton(AF_INET, token, &destaddr);
				inf = rt_get_nexthop(destaddr.s_addr);

				printf(_BBLUE_"\tSENDING TO-> [NEXTHOP %s]\n", token);

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
			}
			if(!strcmp("down",token)){
				if((token = strtok_r(NULL, delim, &data)) == NULL){ print_help(); continue;}
				down_interface(atoi(token));

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


//set MTU of an interface
void set_mtu(int inf_num, int mtu){
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *i = curr->data;
		if(i->id == inf_num){
			i->mtu = mtu;
		}
	}
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


//downs an interface
void down_interface(int id){
	node_t *curr;
	interface_t *inf;

	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		inf = curr->data;
		if(id == inf->id){
			inf->status = DOWN;
			break;
		}
	}

	rtu_routing_entry *route, *tmp;
	HASH_ITER(hh, routing_table, route, tmp){
		if(route->nexthop == inf->sourcevip || route->nexthop == inf->destvip){
			route->cost = 16;
		}
	}
	routing_table_send_update();
}


//ups an interface
void up_interface(int id){

	node_t *curr;
	interface_t *inf;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		inf = curr->data;
		if(id==inf->id){
			inf->status = UP;
			break;
		}
	}

	rtu_routing_entry *route, *tmp;
	HASH_ITER(hh, routing_table, route, tmp){
		if(route->nexthop == inf->sourcevip || route->nexthop == inf->destvip){
			route->cost = 0;
			route->ttl = REFRESH_TIME;
		}
	}

	routing_table_send_update();
}


//When a given packet must be broken down into n fragments, this function will send up to the n-1'th fragment
//how the last fragment is sent is up to the caller
void fragment_send (interface_t *nexthop, char **data, int datasize, uint16_t *offset, uint32_t iporigin, uint32_t ipdest, uint16_t ident){
	*offset += 1<<13;
	int maxpayload = nexthop->mtu - IPHDRSIZE;
	char *dataend = *data + datasize;
	char *packet = malloc(IPHDRSIZE + maxpayload);

	while(*data < dataend-maxpayload){
		int packetsize = encapsulate_inip(iporigin, ipdest, IP, *data, maxpayload, &packet);
		send_ip(nexthop, packet, packetsize);
		*offset+=maxpayload/8;
		*data+=maxpayload;
	}
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

	if(trigger){
		print_routes();
		routing_table_send_update();
	}

	for(curr = credible_entries->head;curr!=NULL;curr=curr->next){
		free((uint32_t *)curr->data);
	}
	list_free(&credible_entries);

	return 0;
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


//send routing table out to everyone
void routing_table_send_update() {
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


interface_t *rt_get_nexthop(uint32_t dest_vip){
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


//send RIP response packet
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


//takes in necessary information (vip, protocol..) and payload buffer. Makes a packet and returns it in char **packet
int encapsulate_inip (uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, int datasize, char **packet)
{
	struct iphdr *h=(struct iphdr *) malloc(IPHDRSIZE);
	memset(h,0,IPHDRSIZE);

	int packetsize = IPHDRSIZE + datasize;

	h->version = 4;
	h->ihl = 5;
	h->tot_len = htons(packetsize);
	h->protocol = protocol;
	h->saddr = src_vip;
	h->daddr = dest_vip;

	memcpy(*packet,h,IPHDRSIZE);
	char *datapart = *packet + IPHDRSIZE;
	memcpy(datapart, data, datasize);
	int checksum = ip_sum(*packet, IPHDRSIZE);
	char *check = *packet + sizeof(uint8_t)*4 + sizeof(uint16_t)*3;
	memcpy(check,&checksum,sizeof(uint16_t));

	//printf("checksum is %d\n", checksum);

	free(h);
	return packetsize;
}


//steps through the received IP packet and packs it back into a struct ip hdr
//also returns a value suggesting whether the packet identified is to be delivered locally or forwarded
int id_ip_packet (char *packet, struct iphdr **ipheader) {

	char *p = packet;
	struct iphdr *i = *ipheader;
	//uint16_t newchecksum;
	memcpy(i, p, sizeof(uint8_t));
	p=p+sizeof(uint8_t)*2;
	memcpy(&(i->tot_len), p, sizeof(uint16_t));
	i->tot_len = ntohs(i->tot_len);
	p=p+sizeof(uint16_t);

	memcpy(&(i->id), p, sizeof(uint16_t));
	p=p+sizeof(uint16_t);
	memcpy(&(i->frag_off),p, sizeof(uint16_t));
	p=p+sizeof(uint16_t)+sizeof(uint8_t);

	memcpy(&(i->protocol), p, sizeof(uint8_t));
	p=p+sizeof(uint8_t); 

	memcpy(&(i->check), p, sizeof(uint16_t));
	memset(p,0,sizeof(uint16_t));

	p=p+sizeof(uint16_t);
	memcpy(&(i->saddr), p, sizeof(uint32_t));
	p=p+sizeof(uint32_t);
	memcpy(&(i->daddr), p, sizeof(uint32_t));

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ((struct in_addr *)&(i->saddr)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((struct in_addr *)&(i->daddr)), dest, INET_ADDRSTRLEN);

	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf=curr->data;
		if(inf->sourcevip == i->daddr){
			return LOCALDELIVERY;
		}
	}
	return FORWARD;
}	


//takes in the next hop's interface and sends the packet to it.
int send_ip (interface_t *inf, char *packet, int packetsize) {
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
	}

	return 0;
}

//reads from the passed in lnx file and make interfaces based on each line.
int setup_interface(char *filename) {

	list_t *links = parse_links(filename);
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];

	for (curr = links->head; curr != NULL; curr = curr->next) {

		link_t *sing = (link_t *)curr->data;

	    	interface_t *inf = (interface_t *)malloc(sizeof(interface_t));
	   	inf->id 	= ++interface_count;
	   	inf->sockfd 	= get_socket(sing->local_phys_port, &srcaddr, SOCK_DGRAM);

		get_addr(sing->remote_phys_port, &destaddr, SOCK_DGRAM, 0);
		inf->destaddr = malloc(sizeof(struct sockaddr));
		inf->sourceaddr = malloc(sizeof(struct sockaddr));

		memcpy(inf->destaddr, destaddr->ai_addr, sizeof(struct sockaddr));
		memcpy(inf->sourceaddr, srcaddr->ai_addr, sizeof(struct sockaddr));
		freeaddrinfo(destaddr);
		freeaddrinfo(srcaddr);

        	inf->sourcevip = ntohl(sing->local_virt_ip.s_addr);
		inf->destvip = ntohl(sing->remote_virt_ip.s_addr);
    		inf->status = UP;
		inf->mtu = MTU;

		inet_ntop(AF_INET, (struct in_addr *) &inf->sourcevip, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (struct in_addr *) &inf->destvip, dest, INET_ADDRSTRLEN);
		printf(_MAGENTA_"\tBringing up interface %s -> %s\n"_NORMAL_, src, dest);

		list_append(interfaces, inf);

		FD_SET(inf->sockfd, &masterfds);
		maxfd = inf->sockfd;
	}

	free_links(links);
	return 0;
}



//does get_addr and all that to set up a socket and returns its fd number to the caller
int get_socket (uint16_t portnum, struct addrinfo **source, int type) {

	struct addrinfo *p;
	int sockfd, yes = 1;

	if(get_addr(portnum, source, type, 1) == -1){
		printf("get_addr()\n");
		exit(1);
	}
 
	for(p = *source; p!=NULL; p=p->ai_next){
		if((sockfd= socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			perror("socket()");
			continue;
		}

		if(bind(sockfd, p->ai_addr, p->ai_addrlen) != 0){
			perror("bind()");
			close(sockfd);
			continue;
		}

		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt()");
			exit(1);
		}
		break;
	}

	if(p==NULL){
		printf("socket set up failed\n");
		exit(1);
	}

	return sockfd;
}


//wrapper function for get_addrinfo() and its steps
int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local) {

	int status;
	struct addrinfo hints;
	char port[32];
	sprintf(port, "%u", portnum);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = type;

	if ((status = getaddrinfo(NULL, port, &hints, addr)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}

	return 1;
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

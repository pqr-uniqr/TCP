/*
 * =====================================================================================
 *
 *       Filename:  interface.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/02/2013 01:37:00 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "interface.h"


int id_address(uint32_t destaddr){
	node_t *curr;
	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *inf = curr->data;
		if(inf->sourcevip == destaddr){
			return 1;
		}
	}
	return 0;
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




int setup_interface(char *filename) {

	list_t *links = parse_links(filename);
	node_t *curr;
	struct addrinfo *srcaddr, *destaddr;
	list_init(&interfaces);
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];

	int interface_count = 0;

	for (curr = links->head; curr != NULL; curr = curr->next) {

		link_t *sing = (link_t *)curr->data;

	    	interface_t *inf = (interface_t *)malloc(sizeof(interface_t));
	   	inf->id 	= ++interface_count;
	   	inf->sockfd 	= get_socket(sing->local_phys_port, &srcaddr, SOCK_DGRAM);

		get_addr(sing->remote_phys_port, &destaddr, SOCK_DGRAM);
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


//ups an interface
void up_interface(const char *arg){
	unsigned id;
	int ret;
	ret = sscanf(arg, "up %u", &id);
	if(ret != 1){
		fprintf(stderr, "syntax error (usage: down[interface])\n");
		return;
	}

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
}


//downs an interface
void down_interface(const char *arg){
	unsigned id;
	int ret;
	ret = sscanf(arg, "down %u", &id);
	if(ret != 1){
		fprintf(stderr, "syntax error (usage: down[interface])\n");
		return;
	}

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
}


//takes in the next hop's interface and sends the packet to it.
int send_ip (interface_t *inf, const char *packet, int packetsize) {
	int bytes_sent;
	char tbs[packetsize];
	memcpy(tbs, packet, packetsize);
	printf("sendto %d\n", inf->sockfd);
	bytes_sent = sendto(inf->sockfd, tbs, packetsize, 0, inf->destaddr, sizeof(struct sockaddr));

	if(bytes_sent == -1){
		perror("sendto()");
		exit(-1);
	}

	return bytes_sent;
}


//does get_addr and all that to set up a socket and returns its fd number to the caller
int get_socket (uint16_t portnum, struct addrinfo **source, int type) {

	struct addrinfo *p;
	int sockfd, yes = 1;

	if(get_addr(portnum, source, type) == -1){
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
int get_addr(uint16_t portnum, struct addrinfo **addr, int type){

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

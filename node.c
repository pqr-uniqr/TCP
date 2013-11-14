#include "node.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int maxfd;
list_t  *interfaces, *routes;
socket_t *fd_list; //hash table (id, socket) 
socket_t *socket_table; //hash table ({urport, myport, uraddr}, socket) 
sockets_on_port *sockets_by_port;
rtu_routing_entry *routing_table;
fd_set readfds, masterfds;
int maxsockfd = 0, expect = 0;
unsigned keylen = offsetof(socket_t, uraddr)
	+sizeof(uint32_t) -offsetof(socket_t, urport); 
time_t lastRIPupdate;


struct {
	int protocol;
	void (*handler)(const char *, interface_t *, int);
} protocol_handlers[] = {
	{RIP, rip_handler},
	{IP, ip_handler},
	{TCP,tcp_handler}
};

struct {
  const char *command;
  void (*handler)(const char *);
} cmd_table[] = {
	{"accept", accept_cmd},
	{"connect", connect_cmd},
	{"help", print_help},
	{"interfaces", print_interfaces},
	{"routes", print_routes},
	{"sockets", print_sockets},
	{"down", down_interface},
	{"up", up_interface}, 
  {"send", send_cmd}, 
  {"recv", recv_cmd}
  /*
	{"sendfile", sendfile_cmd},
  {"recvfile", recvfile_cmd},
  {"shutdown", shutdown_cmd},
  {"close", close_cmd} */
};




int main ( int argc, char *argv[]) {

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}

	//stays here
	char readbuf[CMDBUFSIZE], cmd[CMDBUFSIZE];
	char *fgets_ret; 
	lastRIPupdate = time(NULL);
	time_t t;
	
	srand((unsigned) time(&t));
	//FD_SET(0, &masterfds);
	FD_ZERO(&readfds);
	FD_ZERO(&masterfds);
	maxfd = 2;

	if(setup_interface(argv[1]) == -1){
		printf("ERROR : setup_interface failed\n");
		exit(1);
	}


	if (rt_init() == -1) {
		printf("ERROR : init_routing failed\n");
		exit(1);
	}

	//create recv thrad TODO check errors and shit
	pthread_t recv_thr;
	pthread_attr_t thr_attr;
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&recv_thr, &thr_attr, recv_thr_func, NULL);

	while(1){

		//TODO these functions should be modified to count time

		//command line parsing
			unsigned k;
			int ret;
			(void)fflush(stdout);
			fgets_ret = fgets(readbuf, CMDBUFSIZE, stdin);
			if(fgets_ret == NULL){
				break; //something went terribly wrong?
			}

			ret = sscanf(readbuf, "%s", cmd); 
			if(ret!=1){
				fprintf(stderr, "syntax error (1st argument must be a command)\n");
				continue;
			}

			if(!strcmp(cmd, "q")) break;

			for(k=0;k<sizeof(cmd_table)/sizeof(cmd_table[0]);k++){
				if(!strcmp(cmd, cmd_table[k].command)){
					cmd_table[k].handler(readbuf);
					break;
				}
			}

			if(k == sizeof(cmd_table)/sizeof(cmd_table[0])){
				fprintf(stderr, "no valid command specified\n");
				continue;
			}
		}

	printf("safe exiting\n");

	//clean up memory before exiting


	list_free(&interfaces);

	rtu_routing_entry *entry, *temp;
	HASH_ITER(hh, routing_table, entry, temp){
		HASH_DEL(routing_table, entry);
		free(entry);
	}

	return EXIT_SUCCESS;
}





//initial branching of cases will happen here!
void tcp_handler(const char *packet, interface_t *inf, int received_bytes){
	struct iphdr *ipheader = malloc(sizeof(struct iphdr));
	(void)decapsulate_fromip(packet, &ipheader);
	
	tcphdr *tcpheader = (tcphdr *) malloc(TCPHDRSIZE);
	memcpy(tcpheader, packet+IPHDRSIZE, TCPHDRSIZE);
	tcp_ntoh(tcpheader);

	tcp_print_packet(tcpheader);

	//for first grip packet (SERVER)
	if(SYN(tcpheader->orf) &&!ACK(tcpheader->orf)){
		sockets_on_port *sop = get_sockets_on_port(tcpheader->destport);
		if(sop->listening_socket== NULL){
			printf("we ain't listening on this port\n");
			//TODO send an RST packet
			//tcphdr *rst = tcp_craft(handshake(0, NULL));
			//tcp_hton(rst);
			//goto cleanup; //"we ain't listening on this port"
			free(tcpheader);
			free(ipheader);
			return;
		}

		//TODO check if this guy is already connected

		//make room for 2 uint32_t (IMPORTANT: uncast it from tcphdr)
		void *tbq= realloc(tcpheader, TCPHDRSIZE + 2*SIZE32);
		memcpy(tbq+TCPHDRSIZE, &ipheader->saddr, SIZE32);
		memcpy(tbq+TCPHDRSIZE+SIZE32, &ipheader->daddr, SIZE32);
		NQ(sop->listening_socket->q, tbq);
		//goto cleanup;
	} 

	//if not first grip
	else {
		//it must be an active socket--look for it in hh2 
		socket_lookup_key *key = malloc(sizeof(socket_lookup_key));
		memset(key, 0, sizeof(socket_lookup_key));
		key->urport = tcpheader->sourceport;
		key->myport = tcpheader->destport;
		key->uraddr = ipheader->saddr;
		socket_t *so;	
		HASH_FIND(hh2, socket_table, &key->urport, keylen, so);
		free(key);

		if(so == NULL){
			free(tcpheader);
			free(ipheader);//"non-request packet received from stranger"
			return;
		}


		//second grip (CLIENT)
		if(SYN(tcpheader->orf) && ACK(tcpheader->orf)){
			if(so->state != SYN_SENT){
					//goto cleanup; //"packet inappropriate for current connection state"
			}
			set_socketstate(so, ESTABLISHED);
			so->ackseq= tcpheader->seqnum;
			so->adwindow = tcpheader->adwindow;

			tcp_send_handshake(3, so);
			free(tcpheader);
			free(ipheader);
			return;
		}

		//third grip & beyond
		else {
			//if anything arrives beyond the thidr grip, ESTABLISHED
			if(so->state == SYN_RCVD){
				set_socketstate(so, ESTABLISHED);
				return;
			}

			if(ACK(tcpheader->orf)){
				printf("incr by %d\n", tcpheader->ack_seq - so->myseq);
				so->sendw->lba +=(tcpheader->ack_seq - so->myseq);
				so->myseq = tcpheader->ack_seq;
			} else {
				//data packet received
				recvw_t *rwin = so->recvw;
				int payloadsize = ipheader->tot_len -IPHDRSIZE-TCPHDRSIZE;
				if(CB_FULL(rwin->buf)) return; //not enough space to receive TODO memory
				int cap = CB_GETCAP(rwin->buf);
				//in order?
				if(tcpheader->seqnum == so->ackseq){
					int ret = CB_WRITE(rwin->buf, packet+IPHDRSIZE+TCPHDRSIZE, MIN(cap, payloadsize));
					//there is no gap--straightforward pointer update
					if((int)rwin->lbc+1 == (int)rwin->nbe){
						rwin->lbc += payloadsize -1;
						rwin->nbe += payloadsize;
						so->ackseq += payloadsize;
						so->adwindow -= ( (rwin->nbe-1) - rwin->lbr);
					} else{
						//TODO there is a gap --pointer update
					}
				} else {
						//TODO packet arrived out of order
				}

				//time to send ACK
				tcphdr *ack =tcp_craft_ack(so);
				tcp_hton(ack);
				send_tcp(so, ack, TCPHDRSIZE);
			}
		}

		return;
	}
}


void *accept_thr_func(void *arg){
  int s;
  int ret;

  s = (int)arg;

  while (1){
    ret = v_accept(s, NULL);
    if (ret < 0){
      fprintf(stderr, "v_accept() error on socket %d: %s\n", s, strerror(-ret));
      return NULL;
    }
    printf("v_accept() on socket %d returned %d\n", s, ret);
  }

  return NULL;
}


void accept_cmd(const char *line){
  uint16_t port;
  int ret;
  struct in_addr any_addr;
  int s;
  pthread_t accept_thr;
  pthread_attr_t thr_attr;

  ret = sscanf(line, "accept %" SCNu16, &port);
  if (ret != 1){
    fprintf(stderr, "syntax error (usage: accept [port])\n");
    return;
  }

	printf("accepting on port %d\n", port);

  s = v_socket();
  if (s < 0){
    fprintf(stderr, "v_socket() error: %s\n", strerror(-s));
    return;
  }

  any_addr.s_addr = 0;
  ret = v_bind(s, &any_addr, port);
  if (ret < 0){
    fprintf(stderr, "v_bind() error: %s\n", strerror(-ret));
    return;
  }

  ret = v_listen(s);
  if (ret < 0){
    fprintf(stderr, "v_listen() error: %s\n", strerror(-ret));
    return;
  }

  ret = pthread_attr_init(&thr_attr);
  assert(ret == 0);
  ret = pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
  assert(ret == 0);
  ret = pthread_create(&accept_thr, &thr_attr, accept_thr_func, (void *)s);
  if (ret != 0){
    fprintf(stderr, "pthread_create() error: %s\n", strerror(errno));
    return;
  }
  ret = pthread_attr_destroy(&thr_attr);
  assert(ret == 0);

  return;
}
void connect_cmd(const char *line){
  char ip_string[CMDBUFSIZE];
  struct in_addr ip_addr;
  uint16_t port;
  int ret;
  int s;
  
  ret = sscanf(line, "connect %s %" SCNu16, ip_string, &port);
  if (ret != 2){
    fprintf(stderr, "syntax error (usage: connect [ip address] [port])\n");
    return;
  }

  //ret = inet_aton(ip_string, &ip_addr);
	ret = inet_pton(AF_INET,ip_string,&ip_addr);
  if (ret == 0){
    fprintf(stderr, "syntax error (malformed ip address)\n");
    return;
  }

  s = v_socket();
  if (s < 0){
    fprintf(stderr, "v_socket() error: %s\n", strerror(-s));
    return;
  }
  ret = v_connect(s, &ip_addr, port);
  if (ret < 0){
    fprintf(stderr, "v_connect() error: %s\n", strerror(-ret));
    return;
  }
  printf("v_connect() returned %d\n", ret);

  return;
}


void send_cmd(const char *line){
  int num_consumed;
  int socket;
  const char *data;
  int ret;

  ret = sscanf(line, "send %d %n", &socket, &num_consumed);
  if (ret != 1){
    fprintf(stderr, "syntax error (usage: send [interface] [payload])\n");
    return;
  } 
  data = line + num_consumed;
  if (strlen(data) < 2){ // 1-char message, plus newline
    fprintf(stderr, "syntax error (payload unspecified)\n");
    return;
  }

  ret = v_write(socket, data, strlen(data)-1); // strlen()-1: stripping newline
  if (ret < 0){
    fprintf(stderr, "v_write() error: %s\n", strerror(-ret));
    return;
  }
  printf("v_write() on %d bytes returned %d\n", strlen(data)-1, ret);
	

  return;
}


void recv_cmd(const char *line){
  int socket;
  size_t bytes_requested;
  int bytes_read;
  char should_loop;
  char *buffer;
  int ret;
  
  ret = sscanf(line, "recv %d %zu %c", &socket, &bytes_requested, &should_loop);
  if (ret != 3){
    should_loop = 'n';
    ret = sscanf(line, "recv %d %zu", &socket, &bytes_requested);
    if (ret != 2){
      fprintf(stderr, "syntax error (usage: recv [interface] [bytes to read] "
                                                "[loop? (y/n), optional])\n");
      return;
    }
  }

  buffer = (char *)malloc(bytes_requested+1); // extra for null terminator
  assert(buffer);
  memset(buffer, '\0', bytes_requested+1);
  if (should_loop == 'y'){
   // bytes_read = v_read_all(socket, buffer, bytes_requested);
  }
  else if (should_loop == 'n'){
    bytes_read = v_read(socket, buffer, bytes_requested);
  }
  else {
    fprintf(stderr, "syntax error (loop option must be 'y' or 'n')\n");
    goto cleanup;
  }

  if (bytes_read < 0){
    fprintf(stderr, "v_read() error: %s\n", strerror(-bytes_read));
    goto cleanup;
  }
  buffer[bytes_read] = '\0';
  printf("v_read() on %zu bytes returned %d; contents of buffer: '%s'\n",
         bytes_requested, bytes_read, buffer);

	cleanup:
  free(buffer);
  return;
}



void regular_update(int *updateTimer){
	if(time(NULL) - lastRIPupdate > 5){
		broadcast_rip_table();
		lastRIPupdate = time(NULL);
	}
	//TCP CONNECTION TIMEOUT FEATURE: if we're expecting packets
	/*
	if(expect){
		socket_t *so, *temp;
		expect = 0;
		//find the sockets that are expecting 
		HASH_ITER(hh1, fd_list, so, temp){
			if(so->state==SYN_SENT || so->state==SYN_RCVD){
				//increment timer
				so->timer++;
				//if timed out
				if(so->timer == 3){
					printf("Connection request timeout: please try again\n(the following socket will be removed)\n");
					print_socket(so);
					//TODO remove socket
					destroy_socket(so);
				} else {
					//if not timed out, try again
					printf("retransmission: %d-th trial\n", so->timer+1);
					expect = 1;
					tcphdr *retrans = tcp_craft_handshake(so->state, so); //state macro matches with first arg
					tcp_hton(retrans);
					int r = v_write(so->id, (unsigned char *)retrans, TCPHDRSIZE);
					free(retrans);
				}
			}
		}
	} */
}




/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */
/*FUNCTIONS FROM IP---------------------------------------------------------------  */


void *recv_thr_func(void *nothing){
	struct timeval tv, tvcopy; 
	char recvbuf[RECVBUFSIZE]; 
	int received_bytes;
	struct sockaddr sender_addr;
	socklen_t addrlen= sizeof sender_addr;
	struct iphdr *ipheader;
	interface_t *i;
	node_t *curr;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	//recv_thr_func start here -----------------------------

while(1){

	regular_update(&lastRIPupdate);
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
			//this link is down
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
}

	for(curr=interfaces->head;curr!=NULL;curr=curr->next){
		interface_t *i = (interface_t *)curr->data;
		close(i->sockfd);
		free(i->sourceaddr);
		free(i->destaddr);
		free(i);
	}		//recv_thr_func() ends here-------------------------------------
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

PSEUDOCODE for TCP - Connection Establishment


[TODOS & NOTES]

do connection timeout feature
	*list.c has no deletion feature !!! do this
	*uses a fake int counter: change that to a real time_t timer
	*UTHASH has no support for HASH_DEL on hh1 and hh2 ->temporary solution:
			-add attribute to socket_t that represents deleted state

do determine MAXSEQ

do debug compiler mode

do when to calculate checksum? "DELAYED: NOT A BLOCKING ISSUE"
	*when do we need to calculate checksum? whenever we send something
	->whenever we call v_write():
		1-first grip (connection request)
			v_connect()
		2-second grip 
			v_accept()
		3-third grip
			tcp_handler()
		4-beyond third grip (message transfer & acknowledgement)
			don't know yet 

	*we need a checksum calculation function that takes in:
		1-saddr and daddr
		2-protocol (is known)
		3-tcp length
		4-tcp header
		5-data itself

	*test the function with the TAnode ->//TODO I don't know how TAnode calculates checksum
						//but it ain't looking reasonable
						
						
						

#An in-depth, detailed study on the packet format of the TA node and struct tcphdr

#simplify scenario to actual pseudocode
	-this is just so that it's easier to write the pseudocode for sliding window

# multi-key hashing: what do we need?
	1-lookup by id (file descriptor id)
	2-lookup by myport, urport, uraddr

	solution:
		2 hash tables- one by id, another by myport, urport, and uraddr
		
	#make struct port_lookup_key
	#replacement for having the field listening_socket (fast listening socket lookup)
		-actually, let's keep struct sockets_on_port

	#functions that need fixes:
		#v_socket: makes an unbound socket
			#ID: store with hash handle hh1
		#v_bind: 
			-sets myport
			-sets myaddr to 0  (will be set by v_accept)
			#store in respective sockets_on_port
		#v_listen(): makes a passive socket
			#store in respective sockets_on_port as the listening socket
		#v_accept(): makes an active socket
			-here, we get myport, urport, uraddr
			#store in hh2 hashtable 
		#v_connect(): makes an active socket
			#store in hh2 hashtable
			#store in sockets_on_port
		#fd_lookup():
			#hash lookup by id  (hh1)
		#tcp_handler():
			*hash lookup by socket_lookup_key #getmaxfd():
			#hash_iter by id -> no, just keep a global variable

//TODO how is termination signalled? v_accept returns -1
//when the socket is not listening any more


//TODO : when you do v_close
//	1) delete from hh1
//	2) delete from hh2
//	3) delete from sockets_on_port

#print_tcp_packet function


#pack data offset

#setstate functions

#fix the parameters for cmd functions

//different ways to store and lookup sockets
//hh1 - by id --stored by v_socket()
//hh2 - by (urport, myport, uraddr) --done by v_connect() and v_accept()
//get_sockets_on_port --done by v_bind() (additionally by v_listen for listeners)

#dependenecy stuff
	*1-make sure all the functions are assigned in their correct file
	*2-figure out dependency for each of them
	*3-make the dependency tree
	*4-write the header file for all the files

#write the actual code
	-follow the scenario

//tcp_craft_*() functions do NOT hton() for you

?confusion: will every active socket maintain a thread? no. for active sockets,
	reading from socket will be done manually through the "recv" commmand
	






[the scenario: Three Way Handshake]

A (ip:57) <-> B (ip:157)

	on B: accept 2013
		calls: void accept_cmd()
			s = v_socket()
			any_addr.s_addr = 0 //all address
			v_bind(s, any_addr, 2013)
			v_listen(s)
			pthread_create(accept_thr_func, (void *) s)

	on A: connect 157 2013
		calls: void connect_cmd()
			inet_atoin(ip_string, &ip_addr)
			s = v_socket()
			v_connect(s, ip_addr, port)
				
	on B: first grip received
		calls: void tcp_handler(packet, inf, received_bytes)
			char *tcppart = packet+IPHDRSIZE
			struct tcphdr *tcp = (struct tcphdr *)malloc(sizeof(~~~))
			memcpy(tcp,tcpart,~)
			tcp_ntoh(tcp)
			//srcaddr destaddr srcport destport
			if(tcp->syn && !tcp->ack) //connection request

		calls: int v_accept(s, NULL) (on thread)
			//check if we have a pending request in the queue
			//makes a new socket, creating a "connection"
			newso = v_socket()
			pso = fd_lookup(s, fd_list)
			struct tcphdr *tcp = dequeue(pso->queue)
			v_bind(newso, anyadr, so->port)
			so = fd_lookup(newso, fd_list)
			so->urport = tcp->srcport
			so->uraddr = tcp->srcaddr
			so->seqnum = tcp->seqnum
			so->state = SYN_RCVD
			free(tcp)
			//send a response (seqnum+1)
			return newso
			
	on A: second grip receieved
		calls: void tcp_handler(packet, inf, received_bytes)
			...
			if(tcp->syn && !tcp->ack) //not this case!
			//from here we can assume that the packet is for an active socket?
			else if(tcp->syn && tcp->ack) //this is the case!

	on B: third grip received
		calls: void tcp_handler(packet, inf, received_bytes)
			if(tcp->syn && !tcp->ack)
			else if(tcp->syn && tcp->ack)
			else


[Secondary Scenario: Connection Timeout (from the client)]
v_connect()
	sends a request packet and return
	leaving the socket in state SYN_SENT

The main thread goes back to select()
now, when the instruction pointer reads through the program,
it needs to know that it is "expecting" a packet : 
	*global variable int expect



#it in set_socketstate (that's where all the global variables are extern-ed anyways)
	when v_connect() is called, before it returns, set expect = 1
	when v_accept() is called, set expect = 1 

in the main function: 
	if(expect){
		//do things that you would do if expectation is not met
		*for sockets that are expecting packets (SYN_SENT, SYN_RCVD)
			*increment "timer"
			*if timer is at timeout:
				report timeout to user and remove the socket: hh1, hh2, sop
			*if not:
				if socket is in SYN_SENT
						tcp_craft_handshake(1, socket)
				if socket is in SYN_RCVD
						tcp_craft_handshake(2,socket)
		if no such socket is found,
			expect = 0
	}





[DEFINITIONS]

$macro definition
	//size macros --now in common.h
	#define SIZE32 sizeof(uint32_t)

	//program-wide macros --now in common.h
	#define MAXPORT 131071 //2^17-1
	#define MAXSEQ //TODO how to derive maximum sequence number
	#define NQ dqueue_enqueue //use if confident i.e. NQ(q, data)
	#define DQ dqueue_dequeue //use if confident i.e. DQ(q, &data)

	//macros for tcputil.c --now in tcputil.h
	#define TCPHDRSIZE sizeof(struct tcphdr)
	#define HDRLEN(orf) ((0xf000)>>12)
	#define URG(orf) ((0x20 & orf) >>5)
	#define ACK(orf) ((0x10 & orf) >>4)
	#define PSH(orf) ((0x08 & orf) >>3)
	#define RST(orf) ((0x04 & orf) >>2)
	#define SYN(orf) ((0x02 & orf) >>1)
	#define FIN(orf) ((0x01 & orf))
	#define URG_SET(orf) (orf |= 0x20)
	#define ACK_SET(orf) (orf |= 0x10)
	#define PSH_SET(orf) (orf |= 0x08)
	#define RST_SET(orf) (orf |= 0x04)
	#define SYN_SET(orf) (orf |= 0x02)
	#define FIN_SET(orf) (orf |= 0x01)

	//state machine macros --now in common.h
	#define LISTENING 0
	#define SYN_RCVD 1
	#define SYN_SENT 2
	#define ESTABLISHED 3


$struct definition
	//
	struct socket_t: --FILE:now in socket_table.h
		int id

		//the following three contiguous fields make up the lookup key
		uint16_t urport
		uint16_t myport
		uint32_t uraddr

		uint32_t myaddr
		int state
		int myseq //for now, increment before crafting a new packet
		int urseq //for now (window size = 1), sequence number that you're expecting
		bqueue_t *q
		
		//this is for saving active sockets
		uthash_handle hh1 //lookup by fd
		uthash_handle hh2 //lookup by urport myport uraddr

	//for finding listening sockets
	struct sockets_on_port: --FILE: now in socket_table.h
		uint16_t port
		//int socketcount //is this still necessary?
		list_t *list
		socket_t *listening_socket

		uthash_handle hh

	struct tcphdr{ --FILE:now in tcputil.h
		uint16_t sourceport;
		uint16_t destport;
		uint32_t seqnum;
		uint32_t ack_seq;
		uint16_t orf;
		uint16_t adwindow;
		uint16_t check;
		uint16_t urgptr;
	};

	struct socket_lookup_key{ --FILE:now in socket_table.h
		uint16_t urport;
		uint16_t myport;
		uint32_t uraddr;
	};



$Global Variable Definitions --FILE: now in node and socket_table
	socket_t *fd_list //linked list of tuples: (int fdnumber, socket_t *socket)
	socket_t *socket_table //linked list of tuples: (socket_lookup_key, socket_t)
	int maxsockfd = 0
	unsigned keylen = offsetof(socket_t, uraddr) //this has been tested
		+sizeof(uint32_t) - offsetof(socket_t, urport)
	

$includes
	#include <stddef.h> -- FILE: now in common.h

$function definition 
		void print_sockets() -- FILE: sockets_table
		void print_socket(socket_t *sock) --FILE: sockets_table
	 #void accept_cmd(const char *line) --FILE: now in node
		uint16_t port //TODO string parsing
		pthread_t accept_thr
		pthread_attr_t thr_attr
		struct in_addr any_addr
		//socket(), bind(), listen()
		int s = v_socket()
		any_addr.s_addr = 0
		v_bind(s, &any_addr, port)
		v_listen(s)
		//initialize thread
		pthread_attr_init(&thr_attr) 
		pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED)
		pthread_create(&accept_thr,&thr_attr,accept_thr_func, (void *) s)
		pthread_attr_destroy(&thr_attr)

	#void connect_cmd(const char *line)-- FILE: now in node //TODO ERR CHECKS
		const char *addr, uint16_t port
		struct in_addr ip_addr
		inet_aton(addr, &ip_addr)
		int s = v_socket()
		v_connect(s, &ip_addr, port)
		
	#int v_socket() -- FILE: now in v_api
		struct socket_t *so = malloc(sizeof(socket_t)) //TODO free
		if(so == NULL) return -1 //malloc failed
		memset(so, 0, sizeof(struct socket_t))
		so->id = maxsockfd++
		so->q = malloc(sizeof(struct bqueue_t))
		bqueue_init(so->q) //TODO bqueue_destroy
		//add it to the table of sockets hashed by id
		hash_add(hh1, fd_list, id, sizeof(int), so);
		
		return so->id 

	#int v_bind(int socket, struct in_addr *addr, uint16_t port) -- FILE: now in v_api
		//socket_t *so = malloc(sizeof(socket_t))
		socket_t *so = fd_lookup(socket)
		if(so == NULL) return -1 //"no such socket"
		so->myport = 2013
		so->myaddr = 0 //TODO temporary decision: might be something else?
		sockets_on_port *sop = get_sockets_on_port(port)
		list_append(sop->list, so)
		return 0

	#int v_listen(int socket) -- FILE: now in v_api
		socket_t *so = fd_lookup(socket)
		if(so == NULL) return -1
		sockets_on_port *sop = get_sockets_on_port(so->myport)
		if(sop->listening_socket)
			return -1 //TODO error code "this port already has a listening sock"
		sop->listening_sock = so
		so->state = LISTENING
		return 0

	#int v_accept(int socket, struct in_addr *node) -- FILE: now in v_api
		//lso -- listening socket nso-- new active socket
		socket_t *nso, *lso = fd_lookup(socket)
		struct in_addr anyaddr
		anyaddr.s_addr = 0
		if(lso->state != LISTENING) return -1 //this is not a listening socket
		//get request
		void *request
		DQ(lso->q, &request)

		//make a new socket and fill it with necessary information
		int s = v_socket()
		v_bind(s, &anyaddr, lso->myport)
		nso = fd_lookup(s)
		memcpy(nso->uraddr, request+TCPHDRSIZE, SIZE32) //ipheader->saddr
		memcpy(nso->myaddr, request+TCPHDRSIZE+SIZE32, SIZE32) //ipheader->daddr
		nso->urport = ((struct tcpheader *)request)->srcport
		nso->urseq = ((struct tcpheader *)request)->seqnum
			//TODO Consistency check: incrementation?
		nso->myseq = rand() % MAXSEQ
		nso->state = SYN_RCVD 

		//store in hh2 table
		hash_add(hh2, socket_table, urport, keylen, nso)
		free(request)

		//ifs user wants request origin's address, give it
		if(node != NULL) node->s_addr = nso->

		//send response (second grip)
		struct tcp *second_grip = tcp_craft_handshake(2, nso)
		tcp_hton(second_grip)
		//TODO calculate checksum
		v_write(nso, (unsigned char *)second_grip, TCPHDRSIZE)
		free(second_grip)
		return s

	#int v_connect(int socket, struct in_addr *addr, uint16_t port) -- FILE: now in v_api
		struct in_addr any_addr
		any_addr.s_addr = 0
		//bind to a random port and retrieve it
		v_bind(socket, &any_addr, rand() % MAXPORT)
		socket_t *so = fd_lookup(socket)

		if(so == NULL) return -1 //"no such socket"
		//fill in other information
		so->urport = port
		so->uraddr = addr.s_addr //pass by value right?
		so->myseq = rand() % MAXSEQ
		so->state = SYN_SENT

		//store in respective sockets_on_port struct
		sockets_on_port *sop = get_sockets_on_port(port)
		list_append(sop->list,so)

		//store in hh2 hashtable with urport, myport, uraddr
		hash_add(hh2, socket_table, urport, keylen, so)

		//send a connection message (seqnum, SYN)
		struct tcphdr *request = tcp_craft_handshake(1, so)
		tcp_hton(request)
		//TODO calculate checksum
		v_write(socket, (unsigned char *)request, TCPHDRSIZE)
		free(request) 
	
	/*  DEPRECATED
	int getmaxfd() -- FILE: something with access to fd_list (probably just node.c)
		//loops through fd_list and returns max fd
		node_t *curr
		socket_t *so
		int max = 0
		for(curr=fd_list->head;curr!=NULL;curr=curr->next)
			so = curr->data
			if(so->id > max) max = so->id
		return max
	*/

	
	#socket_t *fd_lookup(int fdnumber) -- FILE:now in socket_table.h
		//use hh1 socket->id to find socket_t and return it 
		socket_t *sock
		HASH_FIND(hh1, fd_list, &fdnumber, sizeof(int), sock)
		return sock

	#sockets_on_port *get_sockets_on_port(uint16_t port) -- FILE: now in socket_table.h
		if(port > MAXPORT) return NULL //"not a valid port number"
		sockets_on_port *sop
		hash_find(hh, socket_table, &port,, sizeof(uint16_t), sop)
		if(sop == NULL)
			sop = malloc(sizeof(sockets_on_port))
			list_t *list = malloc(sizeof(list_t))
			list_init(&list)
			sop->port = port
			hash_add(hh, socket_table, port, sizeof(uint16_t), sop)
			sop->list = list
			sop->listening_socket = NULL
			sop->socketcount = 0
		return sop

	#int v_write(int socket, const unsigned char *buf, uint32_t nbyte) --FILE: now in api.c
		//MTU check
		if(nbyte + IPHDRSIZE > MTU) return -1 
		//get nexthop
		socket_t *so = fd_lookup(socket)
		interface_t *nexthop = get_nexthop(socket->uraddr)
		//encapsulate_inip()
		char *packet = malloc(nbyte+IPHDRSIZE)
		encapsulate_inip(socket->myaddr, socket->uraddr, TCP, buf, nbyte,&packet)
		//send_ip()
		return send_ip(nexthop, packet, nbyte+IPHDRSIZE) //fixed this function
								//so it returns bytes_sent
	

	//TODO How exactly is the checksum calculated?
	uint16_t tcp_checksum(uint32_t saddr, uint32_t daddr, int tcplen, char *packet)
			--FILE: tcputil.c
		char *pseudoh = malloc(SIZE32*2 + tcplen)
		memcpy(pseudoh, saddr, SIZE32)
		memcpy(pseudoh + SIZE32, daddr, SIZE32)
		memcpy(pseudoh + 2*SIZE32, packet, tcplen) 
		int res = ip_sum(pseudoh, SIZE32*2 + tcplen)
		free(pseudoh)
		return res
		
	
	#void tcp_ntoh(struct tcphdr *header) -- FILE: now in tcputil
		tcphdr->sourceport = ntohs(tcphdr->sourceport);
		tcphdr->destport = ntohs(tcphdr->destport);
		tcphdr->seqnum = ntohl(tcphdr->seqnum);
		tcphdr->ack_seq = ntohl(tcphdr->ack_seq);
		tcphdr->orf = ntohs(tcphdr->orf);
		tcphdr->adwindow = ntohs(tcphdr->adwindow);
		tcphdr->check = ntohs(tcphdr->check);
		tcphdr->urgptr= ntohs(tcphdr->urgptr);

	#void tcp_hton(struct tcphdr *header) -- FILE: now in tcputil
		tcphdr->sourceport = htons(tcphdr->sourceport);
		tcphdr->destport = htons(tcphdr->destport);
		tcphdr->seqnum = htonl(tcphdr->seqnum);
		tcphdr->ack_seq = htonl(tcphdr->ack_seq);
		tcphdr->orf = htons(tcphdr->orf);
		tcphdr->adwindow = htons(tcphdr->adwindow);
		tcphdr->check = htons(tcphdr->check);
		tcphdr->urgptr= htons(tcphdr->urgptr);

	//contains MALLOC
	#struct tcphdr *tcp_mastercrafter(uint16_t srcport, uint16_t destport,
					uint32_t seqnum, uint32_t acknum,
					bool fin, bool syn, bool rst, bool psh, bool ack
					uint16_t adwindow) -- FILE: now in tcputil
		//pack it
		struct tcphdr *header = malloc(sizeof(struct tcphdr))
		memset(header, 0, sizeof(struct tcphdr))
		header->sourceport = srcport
		header->destport = destport
		header->seqnum = seqnum
		header->acknum = acknum
		if(fin) FIN_SET(header->orf)
		if(syn) SYN_SET(header->orf)
		if(rst) RST_SET(header->orf)
		if(psh) PSH_SET(header->orf)
		if(ack) ACK_SET(header->orf)
		header->adwindow = adwindow
		//TODO calculate checksum -> just return it, there will be a separate
		//function for this
		return header
	
	//contains MALLOC--I don't think anyone uses this
	#struct tcphdr *tcp_unpack(char *packet)
		struct tcphdr *header = malloc(sizeof(struct tcphdr))
		header = (struct tcphdr *) packet+IPHDRSIZE
		
	"char *encapsulate_intcp()" - not needed until sliding window


	#void tcp_print_packet(struct tcphdr *header) --FILE: now in tcputil
		printf("TCP HEADER---------------\n");
		printf("sourceport %u\n", header->sourceport);
		printf("destport %u\n", header->destport);
		printf("seqnum %lu\n", header->seqnum);
		printf("ack_seq %lu\n", header->ack_seq);
		printf("data offset: %d\n", (header->orf & 0xf000)>>12);
		printf("res: %d\n", (header->orf &0xFC0)>>6);
		printf("flags: \n");
		printf("	URG? %d\n", (header->orf & 0x20)>>5);
		printf("	ACK? %d\n", (header->orf & 0x10)>>4);
		printf("	PSH? %d\n", (header->orf & 0x08)>>3);
		printf("	RST? %d\n", (header->orf & 0x04)>>2);
		printf("	SYN? %d\n", (header->orf & 0x02)>>1);
		printf("	FIN? %d\n", (header->orf & 0x01));
		printf("adwindow: %u\n", header->adwindow);
		printf("check: %u\n", header->check);
		printf("urgptr: %u\n",header->urgptr);
		printf("------------------------\n\n");

		

	//contains MALLOC
	#struct tcphdr *tcp_craft_handshake(int gripnum, socket_t *socket) -- FILE: now in tcputil.c
		switch(gripnum)
			case 1
				//first grip (make seqnum, SYN)
				//int seqnum = rand() % MAXSEQ
				//socket->myseq = seqnum
				//craft the packet
				return tcp_mastercrafter(socket->myport,socket->urport,
							socket->myseq, 0,
							0,1,0,0,0,
							0)
			case 2
				//second grip (make seqnum, SYN, ACK, ack_seq)
				//int seqnum = rand() % MAXSEQ
				//socket->myseq = seqnum
				//craft the packet and return
				return tcp_mastercrafter(socket->myport,socket->urport,
							socket->myseq,++(socket->urseq),
							0,1,0,0,1,
							0)
			case 3 
				//third grip (ACK, ack_seq)
				return tcp_mastercrafter(socket->myport,socket->urport,
							++(socket->myseq),++(socket->urseq),
							0,0,0,0,1
							0,)





$Setup
	time_t t
	srand((unsigned) time(&t))



$Event Loop: void tcp_handler(pack, inf, received_bytes)
	socket_t *so
	node_t *curr
	//IP packet is available as variable "ipheader"
	//get the tcp packet, make a copy and ntoh() it 
	char *tcppart = packet+IPHDRSIZE
	struct tcphdr *tcpheader = (struct tcphdr *) malloc(TCPHDRSIZE)
	memcpy(tcpheader, tcppart, TCPHDRSIZE)
	tcp_ntoh(tcpheader) //this is all the ntoh() this program needs

	//connection request (first grip) - header will be queued - don't FREE
	if(SYN(tcpheader->orf) && !ACK(tcpheader->orf))
		sockets_on_port *sop = get_sockets_on_port(tcpheader->destport)
		if(sop == NULL)
			free(tcpheader)
			return -1 //"packet destined for an impossible port number"
		if(sop->listening_sock == NULL)
			free(tcpheader)
			return -1 //"we ain't listening on this port"	
		if(so != NULL)
			free(tcpheader) //"this guy is already connected"
			return -1
		//connection request needs to include src/dest address
		realloc(tcpheader, TCPHDRSIZE + 2*SIZE32)
		memcpy(tcpheader+ TCPHDRSIZE, ipheader->saddr,SIZE32);
		memcpy(tcpheader+ TCPHDRSIZE + SIZE32,ipheader->daddr,SIZE32);
		//queue the request for the accept thread
		NQ(sop->listening_sock->q, tcpheader)

	//if this is not a connection request, we should be able to find the socket
	//in the hash table
	else: 	
		//make the key
		socket_lookup_key *key = malloc(sizeof(socket_lookup_key))
		memset(key,0,sieof(socket_lookup_key))
		key->urport = tcpheader->sourceport
		key->myport = tcpheader->destport
		key->uraddr = ipheader->saddr
		socket_t *so
		hash_find(hh2,socket_table, &key->urport, keylen,so)
		free(key)
		if(so == NULL)
			free(tcpheader)
			return -1 //"non-request packet received from stranger"

	//second grip received -- packet will be taken into account - FREE tcpheader
	if (SYN(tcpheader->orf) && ACK(tcpheader->orf))
		if(so->state != SYN_SENT)
			free(tcpheader)
			return -1 //"packet inappropriate for current connection state"
		so->state = ESTABLISHED
		//thrid grip
		struct tcphdr *third_grip = tcp_craft_handshake(3, so)
		tcp_hton(third_grip)
		//TODO checksum calculation
		v_write(so, (unsigned char *)third_grip, TCPHDRSIZE)
		free(third_grip)
		free(tcpheader)

	//third grip and beyond
	else
		if(so->state == ESTABLISHED) 
			//TODO sliding window goes here
		else if(so->state == SYN_RCVD) so->state == ESTABLISHED //3WH done
		else //something's fucked up here
			











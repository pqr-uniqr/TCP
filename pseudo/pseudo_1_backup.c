PSEUDOCODE for TCP - Connection Establishment


[TODOS & NOTES]
*An in-depth, detailed study on the packet format of the TA node and struct tcphdr
	*Receive TA node's first grip, unpack it with your own struct, try hton and stuff to
	get the exact structure and byte reordering required to communicate with TAnode

*simplify scenario to actual pseudocode
	-this is just so that it's easier to write the pseudocode for sliding window

*multi-key hashing

*File dependency tree

-tcp_craft_*() functions do NOT hton() for you

*when to calculate checksum?




[the scenario: Three Way Handshake]

A (ip:57) <-> B (ip:157)

	on B: accept 2013
		calls: void accept_cmd()
			s = v_socket()
				//create a new socket (stored at number handle table)
				struct socket_t *so = malloc(sizeof(socket_t))
				list_append(so, fd_list)
			any_addr.s_addr = 0 //all address
			v_bind(s, any_addr, 2013)
				//bind to a port
				socket_t so = "fd_lookup(s, fd_list)"
				so->myport = 2013
				so->myaddr = //TODO what to put in here...
				//(stored at htable list hashed with 2013)
				list_t *list
				hash_find(connection_table, port, list)
				list_append(so)
			v_listen(s)
				//make sure this is the only listening socket on the port
				socket_t so = fd_lookup(s, fd_list);
				list_t *list
				hash_find(connection_table, so->port, list)
				if(list->listening_socket):
					return -1 //TODO error code
				//put it as the listening socket
				list->listening_sock = so 
				so->state= LISTENING
			pthread_create(accept_thr_func, (void *) s)
				//create a thread listening for packets on this socket's
				//queue
	on A: connect 157 2013
		calls: void connect_cmd()
			inet_atoin(ip_string, &ip_addr)
			s = v_socket()
			v_connect(s, ip_addr, port)
				//bind the socket to a random port
				v_bind(s, anyaddr, "random port")
				//find the socket and put ur* info
				socket_t so = fd_lookup(s, fd_list)
				so->urport = port
				so->uraddr = ip_addr
				//TODO send a connection message (seqnum, SYN)
				
	on B: first grip received
		calls: void tcp_handler(packet, inf, received_bytes)
			char *tcppart = packet+IPHDRSIZE
			struct tcphdr *tcp = (struct tcphdr *)malloc(sizeof(~~~))
			memcpy(tcp,tcpart,~)
			tcp_ntoh(tcp)
			//srcaddr destaddr srcport destport
			if(tcp->syn && !tcp->ack) //connection request
				list_t *list
				hash_find(connection_table, tcp->destport, list)
				//make sure we don't already have him connected
				socket_t *so = curr->data
				for(curr = ~~)
					if(so->uraddr == tcp->srcaddr && so->urport == tcp~~)
						break;
				if(so != NULL)
					//TODO "you're already connected--what is this shit?"
					
				else:
					"queue_that(list->listening_sock->queue, tcp)"

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
			//TODO send a response (seqnum+1)
			return newso
			
	on A: second grip receieved
		calls: void tcp_handler(packet, inf, received_bytes)
			...
			if(tcp->syn && !tcp->ack) //not this case!
			//from here we can assume that the packet is for an active socket?
			else if(tcp->syn && tcp->ack) //this is the case!
				list_t *list
				hash_find(connection_table, tcp->destport, list)
				socket_t *so = curr->data
				for(curr = ~~)
					if(so->uraddr == tcp->src && so->urport == tcp~)
						break;
				//make sure we have we have a connection with him
				if(so == NULL)
					//TODO EDGECASE: "I don't have you on my list -- go away"
				//make sure that connection is in the right state(SYN_SENT)
				else if(so->state!= SYN_SENT)
					//TODO EDGECASE: "Why are you saying hi in the middle 
					//of a conversation?"
				//update state to ESTABLISHED
				else
					so->state = ESTABLISHED
				//TODO send back the third grip
				
	on B: third grip received
		calls: void tcp_handler(packet, inf, received_bytes)
			if(tcp->syn && !tcp->ack)
			else if(tcp->syn && tcp->ack)
			else
				//find the recepient socket
				list_t *list
				hash_find(connection_table, tcp->destport,list)
				socket_t *so = curr->data
				for(curr = ~)
					if(so->uraddr==tcp->src&&so->urport==tcp~)
						break;
				//make sure we have a connection
				if(so==NULL)
					//TODO EDGECASE: "We don't have this connection"
				//if the state is set to SYN_RCVD, move to ESTABLISHED
				else if(so->state== SYN_RCVD)
					so->state== ESTABLISHED
				//if already ESTABLISHED, this must be a real data transfer
				else if(so->state== ESTABLISHED)
					//TODO sliding window starts here



[DEFINITIONS]

$macro definition
	#define MAXPORT 131071 //2^17-1
	#define MAXSEQ //TODO how to derive maximum sequence number
	#define TCPHDRSIZE sizeof(struct tcphdr)
	#define SIZE32 sizeof(uint32_t)
	#define NQ dqueue_enqueue //use if confident i.e. NQ(q, data)
	#define DQ dqueue_dequeue //use if confident i.e. DQ(q, &data)

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

	#define LISTENING 0
	#define SYN_RCVD 1
	#define SYN_SENT 2
	#define ESTABLISHED 3


$struct definition
	*we need a socket struct
	struct socket_t: --FILE:connection_table.c
		int id
		uint16_t myport
		uint16_t urport
		uint32_t myadddr
		uint32_t uraddr
		int state
		int myseq //for now, increment before crafting a new packet
		int urseq //for now (window size = 1), sequence number that you're expecting
		bqueue_t *q

	*modify list_t for port-hashed lists to so listening socket can be instantly found
	struct sockets_on_port: --FILE: connection_table.c
		uint16_t port
		list_t *list
		socket_t *listening_socket
		uthash_handle hh

	struct tcphdr{
		uint16_t sourceport;
		uint16_t destport;
		uint32_t seqnum;
		uint32_t ack_seq;
		uint16_t orf;
		uint16_t adwindow;
		uint16_t check;
		uint16_t urgptr;
	}



$Global Variable Definitions
	list_t *fd_list //linked list of tuples: (int fdnumber, socket_t *socket)
			//TODO requires intialization!



$function definition 
	 void accept_cmd(uint16_t port) -- FILE: node.c //TODO ERR CHECKS
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

	void connect_cmd(const char *addr, uint16_t port) -- FILE: node.c //TODO ERR CHECKS
		struct in_addr ip_addr
		inet_aton(addr, &ip_addr)
		int s = v_socket()
		v_connect(s, &ip_addr, port)
		
	int v_socket() -- FILE: api.c
		struct socket_t *so = malloc(sizeof(socket_t)) //TODO free
		if(so == NULL) return -1 //malloc failed
		memset(so, 0, sizeof(struct socket_t))
		so->id = "getmaxfd()"+1
		so->q = malloc(sizeof(struct bqueue_t))
		bqueue_init(so->q) //TODO bqueue_destroy
		list_append(so, fd_list)
		return so->id 

	int v_bind(int socket, struct in_addr *addr, uint16_t port) -- FILE: api.c
		socket_t *so = fd_lookup(socket)
		if(so == NULL) return -1 //"no such socket"
		so->myport = 2013
		so->myaddr = 0 //TODO temporary decision: might be something else?
		sockets_on_port *sop = get_sockets_on_port(port)
		if(sop == NULL) return -1 //"not a valid port number"
		list_append(sop->list, so)
		return 0

	int v_listen(int socket) -- FILE: api.c
		socket_t *so = fd_lookup(socket)
		if(so == NULL) return -1
		sockets_on_port *sop = get_sockets_on_port(so->myport)
		if(sop->listening_socket)
			return -1 //TODO error code "this port already has a listening sock"
		sop->listening_sock = so
		so->state = LISTENING
		return 0

	int v_accept(int socket, struct in_addr *node) -- FILE: api.c
		//lso -- listening socket nso-- new active socket
		socket_t *nso, *lso = fd_lookup(socket)
		struct in_addr anyaddr
		anyaddr.s_addr = 0
		if(lso->state != LISTENING) return -1 //this is not a listening socket
		//check if we have a reqeust pending -- we always will! it's a blocking q!
		void *request
		DQ(lso->q, (void *) &request)
		//if user wants requester address back, give it
		if(node != NULL) node->s_addr = request->srcaddr //TODO 
		if(node != NULL) memcpy(node->s_addr, request+TCPHDRSIZE,SIZE32)

		//make a new socket and fill it with necessary information
		int s = v_socket()
		v_bind(s, &anyaddr, lso->myport)
		nso = fd_lookup(s)
		memcpy(nso->myaddr, request+TCPHDRSIZE, SIZE32)
		memcpy(nso->uraddr, request+TCPHDRSIZE+SIZE32, SIZE32)
		nso->urport = ((struct tcpheader *)request)->srcport
		nso->urseq = ((struct tcpheader *)request)->seqnum
			//TODO Consistency check: incrementation?
		nso->myseq = rand() % MAXSEQ
		nso->state = SYN_RCVD 
		free(request) 

		//send response (second grip)
		struct tcp *second_grip = tcp_craft_handshake(2, nso)
		tcp_hton(second_grip)
		v_write(nso, (unsigned char *)second_grip, TCPHDRSIZE)
		free(second_grip)
		return s

	int v_connect(int socket, struct in_addr *addr, uint16_t port) -- FILE: api.c
		struct in_addr any_addr
		any_addr.s_addr = 0
		v_bind(socket, &any_addr, rand() % MAXPORT)
		socket_t *so = fd_lookup(socket)
h
		if(so == NULL) return -1 //"no such socket"
		so->urport = port
		so->uraddr = addr.s_addr //pass by value right?
		so->myseq = rand() % MAXSEQ
		so->state = SYN_SENT
		//send a connection message (seqnum, SYN)
		struct tcphdr *hdr = tcp_craft_handshake(1, so)
		v_write(socket, (unsigned char *)hdr, TCPHDRSIZE)
		free(hdr) //TODO Consistency check: malloc?
		
	int getmaxfd() -- FILE: something with access to fd_list (probably just node.c)
		//TODO if 2D hashing becomes possible, this needs a fix
		//loops through fd_list and returns max fd
		node_t *curr
		socket_t *so
		int max = 0
		for(curr=fd_list->head;curr!=NULL;curr=curr->next)
			so = curr->data
			if(so->id > max) max = so->id
		return max

	socket_t *fd_lookup(int fdnumber) -- FILE: probably just node.c
		//TODO if 2D hashing becomes possible, this needs a fix
		//returns the socket with this handle	
		//or NULL if not found

	sockets_on_port *get_sockets_on_port(uint16_t port) -- FILE: connection_table.c
		if(port > MAXPORT) return NULL //"not a valid port number"
		sockets_on_port *sop
		hash_find(hh, connection_table, &port,, sizeof(uint16_t), sop)
		if(sop == NULL)
			sop = malloc(sizeof(sockets_on_port))
			list_t *list = malloc(sizeof(list_t))
			sop->port = port
			hash_add(hh, connection_table, port, sizeof(uint16_t), sop)
			sop->list = list
			sop->listening_socket = NULL
		return sop

	int v_write(int socket, const unsigned char *buf, uint32_t nbyte) --FILE:api.c
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
		
	void tcp_ntoh(struct tcphdr *header) -- FILE: tcputil.c
		tcphdr->sourceport = ntohs(tcphdr->sourceport);
		tcphdr->destport = ntohs(tcphdr->destport);
		tcphdr->seqnum = ntohl(tcphdr->seqnum);
		tcphdr->ack_seq = ntohl(tcphdr->ack_seq);
		tcphdr->orf = ntohs(tcphdr->orf);
		tcphdr->adwindow = ntohs(tcphdr->adwindow);
		tcphdr->check = ntohs(tcphdr->check);
		tcphdr->urgptr= ntohs(tcphdr->urgptr);

	void tcp_hton(struct tcphdr *header) -- FILE: tcputil.c
		tcphdr->sourceport = htons(tcphdr->sourceport);
		tcphdr->destport = htons(tcphdr->destport);
		tcphdr->seqnum = htonl(tcphdr->seqnum);
		tcphdr->ack_seq = htonl(tcphdr->ack_seq);
		tcphdr->orf = htons(tcphdr->orf);
		tcphdr->adwindow = htons(tcphdr->adwindow);
		tcphdr->check = htons(tcphdr->check);
		tcphdr->urgptr= htons(tcphdr->urgptr);

	//contains MALLOC
	struct tcphdr *tcp_mastercrafter(uint16_t srcport, uint16_t destport,
					uint32_t seqnum, uint32_t acknum,
					bool fin, bool syn, bool rst, bool psh, bool ack
					uint16_t adwindow) -- FILE: tcputil.c
		//pack it
		struct tcphdr *header = malloc(sizeof(struct tcphdr))
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
		//TODO calculate checksum
	
	//contains MALLOC--I don't think anyone uses this 
	struct tcphdr *tcp_unpack(char *packet)
		struct tcphdr *header = malloc(sizeof(struct tcphdr))
		header = (struct tcphdr *) packet+IPHDRSIZE
		
	"char *encapsulate_intcp()" - not needed until sliding window

	//contains MALLOC
	struct tcphdr *tcp_craft_handshake(int gripnum, socket_t *socket) -- FILE: tcputil.c
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

	//find the destination socket
	//TODO if 2D hashing becomes possible, this needs a fix
	sockets_on_port *sop = get_sockets_on_port(tcpheader->destport)
	if(sop == NULL)
		free(tcpheader)
		return -1 //"dropped: packet destined for an impossible port number"
	if(sop->listening_sock == NULL)
		free(tcp)
		return -1 //"we ain't listening on this port"
	for(curr=sop->list->head;curr!=NULL;curr=curr->next)
		so = curr->data
		if(so->uraddr==ipheader->srcaddr&&so->urport==tcpheader->sourceport)
			break

	//connection request (first grip)	
	if(SYN(tcpheader->orf) && !ACK(tcpheader->orf))
		if(so != NULL)
			free(tcpheader)
			return -1 //"this guy is already connected"
		//connection request needs to include src/dest address
		realloc(tcpheader, TCPHDRSIZE + 2*SIZE32)
		memcpy(tcpheader+ TCPHDRSIZE, ipheader->saddr,SIZE32);
		memcpy(tcpheader+ TCPHDRSIZE + SIZE32,ipheader->daddr,SIZE32);
		//queue the request for the accept thread
		NQ(sop->listening_sock->q, tcpheader)

	//second grip received
	//TODO kinda worried this might include other cases?
	else if (SYN(tcpheader->orf) && ACK(tcpheader->orf))
		if(so == NULL) 
			free(tcpheader)
			return -1 //"non-reqest packets received from stranger"
		if(so->state != SYN_SENT)
			free(tcpheader)
			return -1 //"packet inappropriate for current connection state"
		so->state = ESTABLISHED
		//second grip
		struct tcphdr *second_grip = tcp_craft_handshake(3, so)
		tcp_hton(second_grip)
		v_write(so, (unsigned char *)second_grip, TCPHDRSIZE)
		free(hdr)

	//third grip and beyond
	else
		if(so==NULL)
			free(tcp)
			return -1 //"non-request packets received from stranger"
		if(so->state == ESTABLISHED) 
			//TODO sliding window goes here
		else if(so->state == SYN_RCVD) so->state == ESTABLISHED //3WH done
		else //something's fucked up here
			











[Experimentation with TAnode]



PSEUDOCODE for TCP - Sliding Window


[Scenario 1-3WH & perfect world transmission]
A <----> B 

on B: "accept 2013"
	v_socket
	v_bind(2013)
	v_listen()
		pthread_create(accept_thr_func)

on A: "connect 73 2013"
	v_socket
	v_bind(random local port)
	v_connect(socket, addr, port)
		*populate socket_t information
		"send the first grip"
		"pthread_create(buf_mgmt_func)"  //initiates buffer management thread

on B: *receives first grip
	tcp_handler()
		if(first grip)
			lso = get_sop(tcpheader->destport)->listening_socket
			NQ(lso->listening_socket->recvq, tbq) 

	v_accept()
		DQ(reqeust)
		nso = v_socket()
		v_bind()
		*populate socket_t info
		set_socketstate(nso, SYN_RCVD)
		"pthread_create(&thread_id, &attribute, buf_mgmt_func, (void *)s)"  //buffer mgmt thread
		"send the second grip"

on A: *receives second grip
		tcp_handler()
			*socket lookup
			set to ESTABLISHED
			if(second grip)
				"send the third grip"
				
on B: *receives third grip
		tcp_handler()
			if(socket state == SYN_RCVD) set to ESTABLISHED

------------3WH DONE------------------------------------------------

What can we assume beyond this point?
	-the receiver thread running tcp_handler()
	-the reader thread running on main function
	-the socket thread running buf_mgmt_func()
	-two sockets on the connection
		each with ports, addresses, state=ESTABLISHED
		sendwindow and recvwindow with all the pointers pointing to the 
		initial sequence number byte
		

on A: user types in "send socknum, data"
		send_cmd(const char *line)
			ret = sscanf(line, "send %d %n", &socket, &num_consumed)
			data = line + num_consumed
			ret = "v_write(socket, data, strlen(data)-1)"
				socket_t *so = fd_lookup(socket)
				TH_LOCK(so->sendw->lock)
				//is there space?
				if(CB_FULL(so->sendw->buf))
					return //buffer full, no write possible
				//how much space?
				cap = CB_GETCAP(so->sendw->buf)
				//write as much as possible
				ret = CB_WRITE(so->sendw->buf, data, MIN(capacity,num_consumed))
				//update last byte written
				so->sendw->lbw = so->sendw->lbw + ret;
				TH_ULOCK(so->sendw->lock)
				return ret
					
on A: thread running buf_mgmt_func() reads the buffer and decides to flush
		//SENDER: nagle's algorithm
		//TODO SENDER: if window of 0 is advertised, periodically send probe with 1 byte of data
		//retransmission
		s = (int) arg
		socket_t *so = fd_lookup(s)
		window_t *sendw = so->sendw
		window_t *recvw = so->recv

		while(1)
			pthread_mutex_lock(sendw->lock)
			//NAGLE--Flush or not?
			if(sendw->lbw != sendw->lbs)
				//TODO wraparound
				if(((sendw->lbw-sendw->lbs) >= MSS) && ((sendw->adwindow) >= MSS))
					"buf_flush(sendw->buf, so)"
				else if(sendw->lba == sendw->lbs)
					"buf_flush(sendw->buf, so)"  restrict 
			//RETRANSMISSION--has the earliest unacked packet timed out?
			if(lba has been stagnant && lba < lbs)
				last_inflight_lba_update =the time when this lba was originally set (with lba <lbs)
				if(time() - last_inflight_lba_update > Timeout(in milliseconds))
					DQ(so->retransmisssionq, segment)
					char *packet ="encapsulate_tcpip(segment)"
					send(so, packet)

on B: tcp_handler receives packet containing flushed data
		tcp_handler()
			//TODO RECEIVER: once a window of 0 is advertised, don't ad until window >= MSS
			//TODO send back ACK with updated ackseq, advertiesed window, buffer it
			//(if space is available)
		if(SYN && !ACK) ...
		else ...
			if(SYN && ACK) ...
			else  ...
				if(ACK)  ...
				else restrict
					//so we just got a data packet... what needs to be done?
					//	buffer the data (or not)
					//	update LBC
					//	update NBE
					//	update ack_seq (next sequence number to be ACKed)
					//	update adwindow
					//	send back ACK
					window_t *rwin=so->recvw
					THR_LOCK(rwin->lock)
					int dsize=ipheader->tot_len-IPHDRSIZE-TCPHDRSIZE

					if(CB_FULL(rwin->buf)) //TODO abandon receiving (any other actions?)
					if("is_outofrange(so, tcpheader->seqnum)")//TODO most likely a noop most of the tm
					cap = CB_GETCAP(rwin->buf)  

					//OBJECTIVE: write and update pointers correctly
					if(tcpheader->seqnum == so->ackseq){
						//in order
						ret = CB_WRITE(rwin->buf, tcpheader+TCPHDRSIZE, MIN(cap,dsize))
						rwin->lbc = MAX(rwin->lbc, tcpheader->seqnum+dsize-1)
						int inc = "inc_nbe_by(rwin)"
						rwin->nbe += inc //TODO wraparound
						so->ack_seq += inc //TODO wraparound
						so->adwindow = so->adwindow - ((rwin->nbe-1)-rwin->lbr) //TODO wraparound
					} else {
						//TODO out of order: how to buffer this
					}

					//OBJECTIVE: trust the updated info in socket_t and ack based on it
					"ack(so)"
						tcphdr *ack = tcp_mastercrafter(so->myport,so->urport,
								0, so->ackseq,
								0,0,0,0,1,
								so->adwindow) //make a wrapper for this function
						interface_t *nexthop = get_nexthop(so->uraddr)
						char *packet = malloc(TCPHDRSIZE+IPHDRSIZE)
						encapsulate_inip(so->myaddr,so->uraddr,TCP,(void *)ack,TCPHDRSIZE,&packet)
						send_ip(nexthop, packet,TCPHDRSIZRE+IPHDRSIZE)
					THR_UNLOCK(rwin->lock)
		
on B: "recv socknum, numbytes, n"
		recv_cmd(const char *line)
			//parse arguments
			buffer = (char *)malloc(bytes_requested+1)
			memset(buffer, '\0', bytes_requested+1)
			bytes_read = v_read(socket, buffer, bytes_requested)
				//read data from the receiving buffer 
				socket_t *so = fd_lookup(socket)
				TH_LOCK(so->recvw->lock)
				int toread = MIN(bytes_requested, so->recvw->nbe-so->recvw->lbr) //TODO wraparound
				so->recvw->lbr += toread;
				TH_UNLOCK(so->recvw->lock)
				return CB_READ(socket->recvw, buffer, toread)


[Side Scenarios]
Packets out of order
Packets lost
Sequence number wraparound
Silly Window Syndrome



[Sliding Window, related constraints and agents]

[TODOS & NOTES] # <-this means it's done do <- this means it's not

-why it's impossible to merge packet handler thread and socket thread
	->because someone has to demux the incoming packets

??? HOW DO YOU STORE GAPPED DATA IN CB ???

do we need a generic send() function that will be used by:
	the sending window thread
	buf_mgmt_func()
	ack()
	tcp_craft_handshake() ("after extension")

do window_t
	init function
		sendw->lba=0
		sendw->lbs=0
		sendw->lbw=0
		recvw->lbr=0
		recvw->lbc=0
		recvw->nbe=1

do correspondence between void * to CB (physical seqnum) & sequence numbers (logical seqnum)
	#who moves together? 
		[on RECEIVING WINDOW]
		correspondence between NBE and ackseq
		->algorithm to keep this correspondence:
			whenever NBE is incremented by N:
				increment ackseq by N

		[on SENDING WINDOW]
		correspondence between LBS and seqnum
		->algorithm to keep LBS and seqnum:
			after you send:
				incremented LBS by payload sent

	*how does logical wraparound and physical wraparound relate to each other?

-"TCP always responds to a data segment with an ACK":
	with the "latest ACK number and Advertised window"
	1- if nogap, this is natural, as every segment will call for an incremented ACK number
	2- if gap, packets arriving out of order will fail to change NBE, and in turn seqnum.
			on the sending side, these redundant "complaint ACKs" will be effectively ignored.

#make scenarios that bring out different elements
	*on the notepad

do decouple packet receiving function from main()

do extend tcp_craft_handshake() functions to take care of sending, too

do make struct window with the pointers and helper functions

do setup the pointers for newly initialized socket's windows

do v_write should take in the data, not the packet
	->which means that the v_write calls I've had so far were not really v_writes

#sequence number has to be in bytes
	-The principle: 
			1-update ackseq number when you receive the packet (tcp_handler--active socket section)
				ackseq = ackseq + size of the packet just received
			2-update seqnum when you send a packet (on connection_thread)
				myseq = myseq + size of the new packet
	#change member variable name: urseq -> ackseq
	!!!sequence number stays the same until the third grip arrives (incremented by the 
	size of the data, not the packet)!!!

do how to shoot down the connection/listening thread
do move third grip up (potentially a performance improvement)
do substitute the use of v_write() on handshake
	why? because use of buffering to receiving buffer is restricted to data
	and the initial packets have no data in them--they are just headers
	so for nth grip, we should not be calling v_write on them
	

# put 2 circular buffers in socket_t 
# use goto in tcp handler to make freeing easier
# reflect change in socket_t (listening sockets will have sendq as NULL)
#share window size info in v_write (starting window size 65535)
	#add circular buffers to socket_t
	#initialize it in v_socket with capacity of 65535
	#make craft_handshake() send MAXSEQ 
		*does 3WH preserve its behavior through sliding window?
				for 3WH packets: ("this is assuming that v_write will call enqueue(sendqueue)")
						A: first grip v_write -->
								no data in flight -->flush right away! (creates ACK expectation)

						B: first grip receive --listening socket
								accept_thr_func -->reads right away (not even buffered)
						B: second grip v_write -->done by accept_thr (creates ACK expectation)
								no data in flight -->flush right away

						A: second grip receive (handler takes care)
								do thread ACK expectation must be met -->queue it in the sendqueue
						A: third grip v_write 
								no data in flight --> flush right away 
	
						B: third grip receive 
								do thread ACK expectation must be met -->queue it in the sendqueue
	#store adwindow
	#queue it in the sendqueue


[DEFINITIONS]

$macro definition
	#define MSS //TODO maximum segment size

	#define CB circular_buffer //shortens function calls for circular buffer
	#define CB_INIT circular_buffer_init
	#define CB_GETCAP circular_buffer_get_available_capacity
	#define CB_FULL circular_buffer_is_full
	#define CB_WRITE circular_buffer_write
	#define CB_READ circular_buffer_read
	#define TH_LOCK pthread_mutex_lock
	#define TH_ULOCK pthread_mutex_unlock
	#define NBDQ bqueue_trydequeue //non-blocking dequeue
	#define MIN(a,b) a>b? b:a

	//size macros --now in common.h
	#define SIZE32 sizeof(uint32_t)

	//program-wide macros --now in common.h
	#define MAXPORT 65535//2^17-1
	#define MAXSEQ  65535//TODO how to derive maximum sequence number

	//state machine macros --now in common.h
	#define LISTENING 0
	#define SYN_RCVD 1
	#define SYN_SENT 2
	#define ESTABLISHED 3


$struct definition
	struct window_t:
		CBT *buf
		void *lbw

	struct socket_t: --FILE:now in socket_table.h
		int id
		uint16_t urport
		uint16_t myport
		uint32_t uraddr

		uint32_t myaddr
		uint32_t state
		uint32_t myseq //for now, increment before crafting a new packet
		uint32_t ackseq //sender assumes this is next sequence number expected
		uint32_t adwindow //sender assumes this is (buffersize-amount of data ready to be read)

		bqueue_t *q //queue for the passive sockets
		CB_t *sendw //Sending window
		CB_t *recvw //Receiving window

		uthash_handle hh1 //lookup by fd
		uthash_handle hh2 //lookup by urport myport uraddr

	//for finding listening sockets
	struct sockets_on_port: --FILE: now in socket_table.h
		uint16_t port
		list_t *list
		socket_t *listening_socket
		uthash_handle hh

	struct tcphdr: --FILE:now in tcputil.h
		uint16_t sourceport
		uint16_t destport
		uint32_t seqnum
		uint32_t ack_seq
		uint16_t orf
		uint16_t adwindow
		uint16_t check
		uint16_t urgptr

	struct socket_lookup_key --FILE:now in socket_table.h
		uint16_t urport
		uint16_t myport
		uint32_t uraddr


$Global Variable Definitions --FILE: main & socket_table
	socket_t *fd_list //linked list of tuples: (int fdnumber, socket_t *socket)
	socket_t *socket_table //linked list of tuples: (socket_lookup_key, socket_t)
	int maxsockfd = 0 //for sockfd assignment (assign)
	unsigned keylen; //length of the lookup key
		
	

$includes
	#include <stddef.h> -- FILE: now in common.h


$function definition 
	*int ack(...)
	*int inc_nbe_by(window_t *recvw) 
		//start from the current NBE pointer
		//count how many bytes of new contiguous data we have available
		//return value of this function + NBE must be NBE
	*buf_flush
		//flush data
		//put things in the retransmission queue

	*void buf_mgmt_func(void *arg) --FILE: v_api.c
		int s, ret
		void *dqd 
		
		s = (int) arg;
		socket_t *so = fd_lookup(s);
		while(1):
				//TODO Nagle's algorithm on sending window
				//TODO retransmission concerns
				//TODO reack concerns
				
	*int v_write(int socket, const unsigned char *buf, uint32_t nbyte) --FILE: v_api.c
		//TODO write in the buffer as much as there is space
		//and return 
	
	*int v_read(int socket, unsigned char *buf, uint32_t nbyte) --FILE: v_api.c
		
	#void send_cmd(const char *line) --FILE: node.c
		*copy from TAnode
		int socket is the socket number
		const char *data is the data to be sent
		ret = v_write(socket, data, strlen(data)-1)

	#void recv_cmd(const char *line) --FILE: node.c
		*copy from TAnode
		int socket is the socket number
		size_t bytes_requested is the number of bytes requested
		char should_loop indicates whether we should call v_read_all() or v_read()
		if(should_loop == 'n')
			bytes_read = v_read(socket, buffer, bytes_requested)
		if(should_loop == 'y')
			bytes_read = v_read_all(socket, buffer, bytes_requested)
				while(bytes_read < bytes_requested)
					ret = v_read(s, buf+bytes_read, bytes_requested-bytes_read)
					if(ret == -EAGAIN)
						continue
					if(ret < 0)
						return ret //error?
					if(ret == 0)
						return bytes_read //
					bytes_read += ret
				return bytes_read

	#void set_socketstate(socket_t *so, int state) --FILE: sockets_table
	#void print_sockets() -- FILE: sockets_table
	#void print_socket(socket_t *sock) --FILE: sockets_table
	#void accept_cmd(const char *line) --FILE: now in node
	#void connect_cmd(const char *line)-- FILE: now in node //TODO ERR CHECKS
	#int v_socket() -- FILE: now in v_api
	#int v_bind(int socket, struct in_addr *addr, uint16_t port) -- FILE: now in v_api
	#int v_listen(int socket) -- FILE: now in v_api
	#int v_accept(int socket, struct in_addr *node) -- FILE: now in v_api
	#int v_connect(int socket, struct in_addr *addr, uint16_t port) -- FILE: now in v_api
	#socket_t *fd_lookup(int fdnumber) -- FILE:now in socket_table.h
	#sockets_on_port *get_sockets_on_port(uint16_t port) -- FILE: now in socket_table.h
	#void tcp_ntoh(struct tcphdr *header) -- FILE: now in tcputil
	#void tcp_hton(struct tcphdr *header) -- FILE: now in tcputil
	#struct tcphdr *tcp_mastercrafter(uint16_t srcport, uint16_t destport,
					uint32_t seqnum, uint32_t acknum,
					bool fin, bool syn, bool rst, bool psh, bool ack
					uint16_t adwindow) -- FILE: now in tcputil
	#void tcp_print_packet(struct tcphdr *header) --FILE: now in tcputil
	#struct tcphdr *tcp_craft_handshake(int gripnum, socket_t *socket) -- FILE: now in tcputil.c
	*uint16_t tcp_checksum(uint32_t saddr, uint32_t daddr, int tcplen, char *packet)




$Setup
	time_t t
	srand((unsigned) time(&t))



$Event Loop: void tcp_handler(pack, inf, received_bytes)
	struct iphdr *ipheader
	struct tcphdr *tcpheader
	memcpy(tcpheader, tcppart, TCPHDRSIZE)
	tcp_ntoh(tcpheader) //this is all the ntoh() this program needs


	//received first grip
	if(SYN(tcpheader->orf) && !ACK(tcpheader->orf))
		sockets_on_port *sop = get_sockets_on_port(tcpheader->destport)
		if(sop->listening_socket==NULL)
			//we're not listening on this port
		void *tbq =realloc(tcpheader, TCPHDRSIZE + 2*SIZE32)
		NQ(sop->listening_sock->q, tbq)

	else: 	
		//look up the active socket
		socket_lookup_key *key = malloc(sizeof(socket_lookup_key))
		hash_find(hh2,socket_table, &key->urport, keylen,so)
		if(so == NULL)
			//"non request packet received from stranger"

		//second grip
		if (SYN(tcpheader->orf) && ACK(tcpheader->orf))
			if(so->state != SYN_SENT)
			//"packet inappropriate for current connection state"
			
			//send third grip
			so->state = ESTABLISHED
			struct tcphdr *third_grip = tcp_craft_handshake(3, so)
			tcp_hton(third_grip)
			v_write(so, (unsigned char *)third_grip, TCPHDRSIZE)

		//beyond second grip
		else
			if(so->state==SYN_RCVD) set_socketstate(so, ESTABLISHED);

			if(ACK(tcpheader->orf)):

			else:












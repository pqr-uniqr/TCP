PSEUDOCODE for TCP - Sliding Window (with flow control, retransmission
but no capability to handle out of order packet)


[new TODOs and NOTES]
PRINCIPLE: Whenever possible, don't pass malloc-ed data down or up
	the only exception is tcp_mastercrafter and other functions that use it

PRINCIPLE: SOCKET SEQUENCE/ACKSEQ NUMBER UPDATE
	-a socket's acknowledge number is updated when packet arrives
		!!!always increments together with NBE
	-sequence number (next byte to be sent) is updated when packet goes out
		!!!unless it's a retransmission--sequence number stays the same

PRINCIPLE: Sender must limit the amount of unacked bytes to adwindow at any point

PRINCIPLE: LBA is always the sequence number of the first element in the retransmission q
		-->if the retransmission queue is empty, LBA == LBS

DO: race condition--ACK arriving before packet is added to retransmission queue
					NOT A BLOCKING ISSUE: move on
					But the solution is this: keep a running LBA that is updated
					by the main thread and referenced by the socket thread
					HOWEVER, this might conflict with the "myseq-only wraparound" solution

#: wrap around
	initial capacity should be registered as the corresponding window's max sequence number
	receiver should be able to wrap ACK around
	sender should be able to wrap his SEQ around

DO: keep a running average of RTT

DO: hton and ntoh for data

DO: v_read_all behavior (small fix)

DO: locking data structure: CB already has a lock--should i just expand CB

#: Sequence number has to be 2*window size

#: Retransmission queue
	#- add segments to retransmission queue when flushing
			keep lba as the seqnum of the first segment in this queue
	#- remove segments from queue when ack is received
			keep lba as the seqnum of the first ....
	#- make mgmt function keep an eye on the timeout
	
#: sending window is no longer in charge of taking care of last byte acknowledged

#: Delayed ACK-- scenario --> ABORTED: NOT INCLUDED IN OUR RFC

#: put packet handler as a seprarate thread (detach that shit)
			-> this will allow for blocking commands to run

#: put scenario 1 in place
	#1 - MACROS 
	#2 - STRUCTS
	#3 - SETUP
	#4 - FUNCTIONS

#: pointer math must be done with pointers cast to int

#: ACK bit is always set 
	12314141!!! right now, handler handles ACK segments separately-- fix this!
	to make get some closure from the inorder scenario, make sure node is checking
	to see if it received what it expected




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
		send the first grip
		"set up sending and receiving window"
			1 - malloc space for sending and receiving window
			2 - initialize circular buffers
			3 - set up pointers for both windows (REMEMBER, NBE is +1!!)
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
		"set up sending and receiving window"
		"pthread_create(&thread_id, &attribute, buf_mgmt_func, (void *)s)"  //buffer mgmt thread
		send the second grip

on A: *receives second grip
		tcp_handler()
			*socket lookup
			set to ESTABLISHED
			if(second grip)
				send the third grip
				
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
			const char *data: is the pointer to the data
			int num_consumed: is the number of bytes user put in for send
				what happens if this doesn't match the exact length of the data?
					1-if num_consumed > strlen(data):
							send strlen(data) bytes
					2-if num_consumed < strlen(data):
							send num_consumed  bytes
					--> basically, send MIN(num_consumed, strlen(data))

			now call "v_write(socket, data, strlen(data)-1)":
				what does this do? non-blocking write to the sending window buffer

				//get socket
				socket_t *so = fd_lookup(socket)
				//is there space?
				if(CB_FULL(so->sendw->buf))
					return //buffer full, no write possible, return 0
				//how much space?
				cap = CB_GETCAP(so->sendw->buf)
				//write as much as possible
				ret = CB_WRITE(so->sendw->buf, data, MIN(capacity,num_consumed))
				//update last byte written
				so->sendw->lbw += ret //TODO wrap
				return ret
					
on A: thread running buf_mgmt_func() reads the buffer and decides to flush
		What does this thread do?
		#- It uses nagle's algorithm to decide when to send + adwindow availability
		2- if adwindow is set to 0, this thread sends probe packet "every second"
		3- if some "sent" data is not acked for more than "timeout", retransmits it
		4- for every ACK received, it calculates RTT and uses it to maintain reasonable timeout
		CONCERNS:
			1- circular buffer already has a lock-buf if we want to keep our own set of pointers,
			we probably do want to lock this
			2- it might not be a bad idea to put adwindow inside sending window, and current
			sequence number (that we are expecting) inside the receveiving window

		//setup
		s = (int) arg
		socket_t *so = fd_lookup(s)
		sendw_t *sendw = so->sendw
		int unsent_bytes, unacked_bytes
		//get to werk
		while(1)
			if(!so->adwindow){
				//adwindow is 0 -- run the timer or set up timer for probe packets
				continue;
			}
			//do we have data to send?
			unsent_bytes = sendw->lbw - sendw->lbs //TODO wrap
			unacked_bytes = sendw->lbw - sendw->lba //TODO wrap

			if(unsent_bytes)
				if((unsent_bytes >= MSS) && ((sendw->adwindow) >= MSS))
					socket_flush(so);
				else if(!unacked_bytes && sendw->adwindow >= unacked_bytes)
					socket_flush(so);
					"socket_flush(socket_t *so)"
						We need to send out everything in the sending window: What do we do?
							1-loop through in chunks of MSS, package data inside TCP header
							2-send it away using send_tcp()
							3-update last byte sent
							4-update my sequence number (next sequence to be sent)
							4-?? WHAT IF GAP? WHY WOULD THERE BE A GAP IN THE SENDING WINDOW?

							sendw_t *sendw = so->sendw
							int tosend
							while(!CB_EMPTY(sendw->buf))
								tosend = MIN(MSS, CB_SIZE(sendw->buf))
								void *payload = malloc(tosend)
								CB_READ(sendw->buf, payload, tosend)
								char *tcppacket = malloc(TCPHDRSIZE+tosend)
								encapsulate_intcp(so, payload, tosend, tcppacket)
								sent += send_tcp(so, tcppacket, tosend+TCPHDRSIZE)

								//TODO store in retrans queue with timestamp
								retrans_t *el = malloc(sizeof(retrans_t))
								el->seqnum = so->myseq
								el->seglen = tosend
								gettimeofday(&el->lastsent, NULL)
								el->data = payload
								el->retrans_count = 0
								DL_APPEND(sendw->retrans_q_head, el)

								so->myseq+=tosend //TODO wrap
								free(tcppacket)

			//RETRANSMISSION--has the earliest unacked packet timed out?
			/*
			if(lba has been stagnant && lba < lbs)
				last_inflight_lba_update =the time when this lba was originally set (with lba <lbs)
				if(time() - last_inflight_lba_update > Timeout(in milliseconds))
					DQ(so->retransmisssionq, segment)
					char *packet ="encapsulate_tcpip(segment)"
					send(so, packet) */

on B: tcp_handler receives packet containing flushed data
		tcp_handler()
			//TODO RECEIVER: once a window of 0 is advertised, don't ad until window >= MSS
			//TODO send back ACK with updated ackseq, advertiesed window, buffer it
			//(if space is available)
		if(SYN && !ACK) ...
		else ...
			if(SYN && ACK) ...
			else  ...
				if(ACK) 
					So we just got a data packet with an ACK in it: What do we do?
						0-read the ack number
						1-check if we can receive anything
						2-check if this packet is "within our receiving range": for now, do nothing
						3-check if this packet is in order VS out of order
						4-buffer the data (CB_WRITE)
						5-update LAST BYTE RECEIVED : MAX(currentLBC, newLBC)
						6-update NEXT BYTE EXPECTED
						7-update ackseq (next sequence number to be ACKed)
						8-update adwindow : how much space do we have left in our recv buffer?
						9-respond to the packet with an ACK (acknowledge NBE -1)

					int acked_bytes = lbs - lba - (myseq - ackseq) //TODO wrap
					int unacked_bytes = lbs - lba - acked_bytes //TODO wrap

					so->sendw->lba += acked_bytes
					CB_READ(so->sendw->buf, NULL, acked_bytes)

					if(!acked_bytes && uncked_bytes):
						//if this ack has no effect + we have unacked bytes

					recvw_t *rwin = so->recvw
					int payloadsize = ipheader->tot_len-IPHDRSIZE-TCPHDRSIZE

					//any data in here?
					if(payloadsize)
					//is there space?
					if(CB_FULL(rwin->buf)) //TODO abandon receiving (any other actions?)
					cap = CB_GETCAP(rwin->buf)  

					//OBJECTIVE: write and update pointers correctly
					//is this what we've been expecting?
					if(tcpheader->seqnum == so->ackseq):
						//packet arrived in order!
						ret = CB_WRITE(rwin->buf, tcpheader+TCPHDRSIZE, MIN(cap,dsize))

						//if no gap
						if(rwin->lbc + 1 == rwin->nbe):
							rwin->lbc += payloadsize -1 //TODO wrap
							rwin->nbe = rwin->lbc + 1  //TODO wrap
							so->ackseq += payloadsize //TODO wrap
							so->adwindow -= ( (rwin->nbe - 1) - rwin->lbr) //TODO wrap
						else:
							//TODO there is a gap
							
					else:
						//TODO out of order: how to buffer this

					//now let's ack this
					tcphdr *ack = "tcp_craft_ack(so)"
					tcp_hton(ack)
					send_tcp(so, ack, TCPHDRSIZE);

on B: "recv socknum, numbytes, n"
		recv_cmd(const char *line)
			
			int socket: is the socket fd id
			size_t bytes_requested: is number of bytes that user wants
			int bytes_read: is number of bytes
			char should_loop: 'y'--> read_all() (BLOCKS) 'n'-->read() (NO BLOCKS)


			bytes_read = v_read(socket, buffer, bytes_requested)
			"v_read(int socket, unsigned char *buf, uint32_t nbyte)"
				The user wants to read numbytes bytes of data (if available) -- what do we do?
					1-check if there's data available
					2-read the data
					3-update LAST BYTE READ
				socket_t *so = fd_lookup(socket)
				recvw_t *recvw = so->recvw
				int toread = MIN(nbyte, (recvw->nbe) - (recvw->lbr) -1 ) 
				recvw->lbr += toread
				return CB_READ(socket->recvw, buffer, toread)


on A: buf_mgmt checks if anything on retransmission queue has timed out
	buf_mgmt(void *arg)
		int s = (int) arg
		socket_t *so = fd_lookup(s)
		sendw_t *sendw = so->sendw
		int unsent_bytes, unacked_bytes

		retrans_t *elt
		struct timeval nowt;

		while(1):
			if(!so->adwindow) continue //probe
			unsent bytes = ~~
			unacked_bytes = 

			//there's unacked bytes: must be something in the retrans q
			if(unacked_bytes){
				//TODO performance concern (we should be able to check just the head)
				DL_FOREACH(sendw->retrans_q_head, elt){
					gettimeofday(&nowt)
					double now = nowt.tv_sec + (nowt.tv_usec /1000000.0)
					double then = elt->lastsent.tv_sec + (elt->lastsent.tv_usec/1000000.0)
					if(now - then > TIMEOUT) //timeout is a fixed macro (for now)
						elt->retrans_count++
						char *tcppacket = malloc(TCPHDRSIZE+elt->seglen)
						encapsulate_intcp(so, elt->data, elt->seglen, tcppacket)
						send_tcp(so, tcppacket, elt->seglen + TCPHDRSIZE)
						gettimeofday(&elt->lastsent, NULL)
				}
			}

			if(unsent_bytes){
				
			}

on A: tcp_handler receives an ACK
		tcp_handler()
		if(SYN && !ACK)
		else
			if(SYN && ACK)
			else 
				if(ACK)
				so we just got an ACK, possibly piggybacked on data--but we're only concerned about
				the ACK at the moment--what do we do?
				1- if this acknowledges new bytes, delete things from the retransmission queue
				and update LBA (which is only kept track of in the sequence number space, meaning
				you only need to update ack_seq
				2- if this is a duplicate ack, keep count of it and retransmit if necessary

				if(there is anything unacknowledged):
				
				

				




[Side Scenarios]
Packets out of order
Packets lost
Sequence number wraparound
Silly Window Syndrome



[DEFINITIONS]

$macro definition
	#define MSS 

	#define TIMEOUT 1

	#define CB circular_buffer //shortens function calls for circular buffer
	#define CB_INIT circular_buffer_init
	#define CB_GETCAP circular_buffer_get_available_capacity
	#define CB_SIZE circular_buffer_get_size
	#define CB_FULL circular_buffer_is_full
	#define CB_WRITE circular_buffer_write
	#define CB_READ circular_buffer_read
	#define CB_EMPTY circular_buffer_is_empty
	#define MIN(a,b) a>b? b:a

	#define TH_LOCK pthread_mutex_lock
	#define TH_ULOCK pthread_mutex_unlock
	#define NBDQ bqueue_trydequeue //non-blocking dequeue


	//program-wide macros --now in common.h
	#define MAXPORT 65535//2^17-1
	#define MAXSEQ 65535 //TODO how to derive maximum sequence number

	//state machine macros --now in common.h
	#define LISTENING 0
	#define SYN_RCVD 1
	#define SYN_SENT 2
	#define ESTABLISHED 3


$struct definition

	struct sendw_t
		CBT *buf
		unsigned char *lbw //last byte written
		unsigned char *lbs //last byte sent
		unsigned char *lba //last byte acknowledged
		pthread_mutex_t lock

	struct recvw_t
		CBT *buf
		unsigned char *lbc //last byte received
		unsigned char *nbe //next byte expected
		unsigned char *lbr //last byte read
		pthread_mutex_t lock

	struct socket_t: --FILE:now in socket_table.h
		int id
		uint16_t urport
		uint16_t myport
		uint32_t uraddr
		uint32_t myaddr
		uint32_t state

		uint32_t myseq //byte # where next transmission begins (not retransmission though)
		uint32_t ackseq //next sequence number that the socket expects
		uint32_t adwindow //sender assumes this is (buffersize-amount of data ready to be read)
											//on the receiver
		bqueue_t *q //queue for the passive sockets
		sendw_t *sendw //Sending window
		recvw_t *recvw //Receiving window

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
	*int v_write(int socket, const unsigned char *buf, uint32_t nbyte) --FILE: v_api.c
		socket_t *so = fd_lookup(socket);
		if(CB_FULL(so->sendw->buf)) return 0; //"no write possible"
		int cap = CB_GETCAP(so->sendw->buf);
		int ret = CB_WRITE(so->sendw->buf, buf, MIN(cap, nbyte));
		so->sendw->lbw = so->sendw->lbw + ret;
		return ret;
	*void buf_mgmt(void *arg) --FILE: srwindow
		
	*void socket_flush(socket_t *so) --FILE: srwindow
	*int v_read(int socket, unsigned char *buf, uint32_t nbyte) --FILE: v_api.c

	*void encapsulate_intcp(socket_t *so, void *data, int datasize, char *packet)--FILE: tcp_util
	*int send_tcp(socket_t so, char *tcppacket, int size) --FILE: tcp_util
		
	#void send_cmd(const char *line) --FILE: node.c
		*copy from TAnode
	#void recv_cmd(const char *line) --FILE: node.c
		*copy from TAnode
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










[TODOS & NOTES] # <-this means it's done do <- this means it's not

-why it's impossible to merge packet handler thread and socket thread
	->because someone has to demux the incoming packets

??? HOW DO YOU STORE GAPPED DATA IN CB ??? 

do we need a generic send() function that will be used by:
	the sending window thread
	buf_mgmt_func()
	ack()
	tcp_craft_handshake() ("after extension")

*checksum field is actually not hton()-ed

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

do leave malloc for mastercrafter function up to the caller

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


#include "node.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

//undefine to see no printf()s

struct sendrecvfile_arg {
  int s;
  int fd;
};

int maxfd, dup_count = 0;
list_t  *interfaces, *routes;
socket_t *fd_list; //hash table (id, socket) 
socket_t *socket_table; //hash table ({urport, myport, uraddr}, socket) 
sockets_on_port *sockets_by_port;
rtu_routing_entry *routing_table;
fd_set readfds, masterfds;
int maxsockfd = 3, expect = 0;
unsigned keylen = offsetof(socket_t, uraddr)
	+sizeof(uint32_t) -offsetof(socket_t, urport); 
time_t lastRIPupdate;
struct timeval span;

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
  {"recv", recv_cmd},
  {"sendfile", sendfile_cmd},
  {"recvfile", recvfile_cmd},
  {"shutdown", shutdown_cmd},
  {"close", close_cmd},
};


int main ( int argc, char *argv[]) {

	if(argc < 1){
		printf("usage: node lnxfilename\n");
		exit(1);
	}

	//stays here
	char readbuf[CMDBUFSIZE], cmd[CMDBUFSIZE];
	char *fgets_ret; 

	//setup timer for regular RIP update
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

	//create recv thrad 
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

	//TODO clean up memory before exiting
	list_free(&interfaces);

	/* 
	socket_t *entr, *tem;
	HASH_ITER(hh1,socket_table, entr, tem){
		HASH_DELETE(hh1,socket_table,entr);
		circular_buffer_free(&entr->sendw->buf);
		circular_buffer_free(&entr->recvw->buf);
		free(entr->sendw);
		free(entr->recvw);
		free(entr);
	} */

	rtu_routing_entry *entry, *temp;
	HASH_ITER(hh, routing_table, entry, temp){
		HASH_DEL(routing_table, entry);
		free(entry);
	}
	return EXIT_SUCCESS;
}

//sendfile ../testfiles/small.01.txt 10.116.89.157 1000
//sendfile testfiles/small.01.txt.csv 10.116.89.157 1000
//recvfile /dev/stdout 1000
void close_cmd(const char *line) {

  int ret;
  int socket;

  ret = sscanf(line, "close %d", &socket);
  if (ret != 1){
    fprintf(stderr, "syntax error (usage: close [socket])\n");
    return;
  }

  ret = v_close(socket);
  if (ret < 0){
    fprintf(stderr, "v_close() error: %s\n", strerror(-ret));
    return;
  }

  printf("v_close() returned %d\n", ret);
  return;
}

void shutdown_cmd(const char *line){
 
  char shut_type[LINE_MAX];
  int shut_type_int;
  int socket;
  int ret;

  ret = sscanf(line, "shutdown %d %s", &socket, shut_type);
  if (ret != 2){
    fprintf(stderr, "syntax error (usage: shutdown [socket] [shutdown type])\n");
    return;
  }

  if (!strcmp(shut_type, "read")){
    shut_type_int = SHUTDOWN_READ;
  }
  else if (!strcmp(shut_type, "write")){
    shut_type_int = SHUTDOWN_WRITE;
  }
  else if (!strcmp(shut_type, "both")){
    shut_type_int = SHUTDOWN_BOTH;
  }
  else {
    fprintf(stderr, "syntax error (type option must be 'read', 'write', or "
                    "'both')\n");
    return;
  }

  ret = v_shutdown(socket, shut_type_int);
  if (ret < 0){
    fprintf(stderr, "v_shutdown() error: %s\n", strerror(-ret)); 
    return;
  }

  printf("v_shutdown() returned %d\n", ret);
  return;
}

void *recvfile_thr_func(void *arg){
  int s;
  int s_data;
  int fd;
  int ret;
  struct sendrecvfile_arg *thr_arg;
  int bytes_read;
  char buf[FILE_BUF_SIZE];

  thr_arg = (struct sendrecvfile_arg *)arg;
  s = thr_arg->s;
  fd = thr_arg->fd;
  free(thr_arg);

	socket_t *so = fd_lookup(s);

  s_data = v_accept(s, NULL);
	so = fd_lookup(s_data);

  if (s_data < 0){
    fprintf(stderr, "v_accept() error: %s\n", strerror(-s_data));
    return NULL;
  }

  ret = v_close(s);
  if (ret < 0){
    fprintf(stderr, "v_close() error: %s\n", strerror(-ret));
    return NULL;
  }

	//must keep here until the sending guy says it's done
  while (so->state < CLOSE_WAIT){
		bytes_read = v_read(s_data, buf, FILE_BUF_SIZE);
    if (bytes_read < 0){
      fprintf(stderr, "v_read() error: %s\n", strerror(-bytes_read));
      break;
    }

    ret = write(fd, buf, bytes_read);
		#ifdef DEBUG
		if(ret > 0){
			printf(_CYAN_"I/O: %d bytes written to file\n"_NORMAL_, ret);
		}
		#endif
    if (ret < 0){
      fprintf(stderr, "write() error: %s\n", strerror(errno));
      break;
    }
  }

  ret = v_close(s_data);
  if (ret < 0){
    fprintf(stderr, "v_close() error: %s\n", strerror(-ret));
  }

	//for receiving retransmitted stuff
	//receive until... what should be the termination condition?
	//until there's nothing to be read && we don't have out of order packets hanging
	while((bytes_read = v_read(s_data,buf, FILE_BUF_SIZE)) ||
			so->recvw->oor_q_size){
		if(bytes_read<0) break;
		if(!bytes_read) break;
		ret = write(fd, buf, bytes_read);
		#ifdef DEBUG
		if(ret > 0){
			printf(_CYAN_"I/O: %d bytes written to file (retransmission)\n"_NORMAL_,
				ret, so->state);
		}
		#endif
		if(ret<0){
			fprintf(stderr, "write() error:%s\n", strerror(errno));
			break;
		}
	}
	
	

  ret = close(fd);
  if (ret == -1){
    fprintf(stderr, "close() error: %s\n", strerror(errno));
  }

  printf("recvfile on socket %d done", s_data);
  return NULL;
}

void recvfile_cmd(const char *line){

  int ret;
  char filename[LINE_MAX];
  uint16_t port;
  int s;
  struct in_addr any_addr;
  pthread_t recvfile_thr;
  pthread_attr_t thr_attr;
  struct sendrecvfile_arg *thr_arg;
  int fd;

  ret = sscanf(line, "recvfile %s %" SCNu16, filename, &port);
  if (ret != 2){
    fprintf(stderr, "syntax error (usage: recvfile [filename] [port])\n");
    return;
  }

  s = v_socket();
  if (s < 0){
    fprintf(stderr, "v_socket() error: %s\n", strerror(-s));
    return;
  }
  any_addr.s_addr = 0;
  ret = v_bind(s, any_addr.s_addr, port);
  if (ret < 0){
    fprintf(stderr, "v_bind() error: %s\n", strerror(-ret));
    return;
  }
  ret = v_listen(s);
  if (ret < 0){
    fprintf(stderr, "v_listen() error: %s\n", strerror(-ret));
    return;
  }
  fd = open(filename, O_WRONLY | O_CREAT);
  if (fd == -1){
    fprintf(stderr, "open() error: %s\n", strerror(errno));
  }
  thr_arg = (struct sendrecvfile_arg *)malloc(sizeof(struct sendrecvfile_arg));
  assert(thr_arg);
  thr_arg->s = s;
  thr_arg->fd = fd;
  ret = pthread_attr_init(&thr_attr);
  assert(ret == 0);
  ret = pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
  assert(ret == 0);
  ret = pthread_create(&recvfile_thr, &thr_attr, recvfile_thr_func, thr_arg);
  if (ret != 0){
    fprintf(stderr, "pthread_create() error: %s\n", strerror(errno));
    return;
  }
  ret = pthread_attr_destroy(&thr_attr);
  assert(ret == 0);

  return;
}



int v_write_all(int s, const void *buf, size_t bytes_requested){
  int ret;
  size_t bytes_written;

  bytes_written = 0;
  while (bytes_written < bytes_requested){
    ret = v_write(s, buf + bytes_written, bytes_requested - bytes_written);
    if (ret == -EAGAIN){
      continue;
    }
    if (ret < 0){
      return ret;
    }
    bytes_written += ret;
  }
  return bytes_written;
}


void *sendfile_thr_func(void *arg){

  int s;
  int fd;
  int ret;
  struct sendrecvfile_arg *thr_arg;
  int bytes_read;
  char buf[FILE_BUF_SIZE];

  thr_arg = (struct sendrecvfile_arg *)arg;
  s = thr_arg->s;
  fd = thr_arg->fd;
  free(thr_arg);

	//will write to circular buffer until end of file
	//reads at most 1024 bytes
  while((bytes_read = read(fd, buf, sizeof(buf))) != 0){
    if (bytes_read == -1){
      fprintf(stderr, "read() error: %s\n", strerror(errno));
      break;
    }

		#ifdef DEBUG
		printf(_CYAN_"I/O: %d bytes read from file\n"_NORMAL_, bytes_read);
		#endif
		
		//will block until everything in the buffer is written
    ret = v_write_all(s, buf, bytes_read);

    if (ret < 0){
      fprintf(stderr, "v_write() error: %s\n", strerror(-ret));
      break;
    }
    if (ret != bytes_read){
			//printf("ret %d bytes_read %d\n", ret, bytes_read);
      break;
    }
  }

	//what about retransmission??? buffer mgmt will take care of it
	//--v_close will not close down buf_mgmt thread until 
	//retransmission queue and sending window are empty
  ret = v_close(s);

  if (ret < 0){
    fprintf(stderr, "v_close() error: %s\n", strerror(-ret));
  }
  ret = close(fd);
  if (ret == -1){
    fprintf(stderr, "close() error: %s\n", strerror(errno));
  }

  printf("sendfile on socket %d done\n", s);
  return NULL;
}

void sendfile_cmd(const char *line){

  int ret;
  char filename[LINE_MAX];
  char ip_string[LINE_MAX];
  struct in_addr ip_addr;
  uint16_t port; 
  int s;
  int fd;
  struct sendrecvfile_arg *thr_arg;
  pthread_t sendfile_thr;
  pthread_attr_t thr_attr;

  ret = sscanf(line, "sendfile %s %s %" SCNu16, filename, ip_string, &port);
  if (ret != 3){
    fprintf(stderr, "syntax error (usage: sendfile [filename] [ip address]"
                                                  "[port])\n");
    return;
  }
  ret = inet_aton(ip_string, &ip_addr);
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
  
  fd = open(filename, O_RDONLY);

  if (fd == -1){
    fprintf(stderr, "open() error: %s\n", strerror(errno));
  }
  thr_arg = (struct sendrecvfile_arg *)malloc(sizeof(struct sendrecvfile_arg));
  assert(thr_arg);
  thr_arg->s = s;
  thr_arg->fd = fd;
  ret = pthread_attr_init(&thr_attr);
  assert(ret == 0);
  ret = pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
  assert(ret == 0);
  ret = pthread_create(&sendfile_thr, &thr_attr, sendfile_thr_func, thr_arg);
  if (ret != 0){
    fprintf(stderr, "pthread_create() error: %s\n", strerror(errno));
    return;
  }
  ret = pthread_attr_destroy(&thr_attr);
  assert(ret == 0);

  return;
}

int v_read_all(int s, void *buf, size_t bytes_requested){
  int ret;
  size_t bytes_read;

  bytes_read = 0;
  while (bytes_read < bytes_requested){
    ret = v_read(s, buf + bytes_read, bytes_requested - bytes_read);
		
    if (ret == -EAGAIN){
      continue;
    }
    if (ret < 0){
      return ret;
    }
    if (ret == 0){
      fprintf(stderr, "warning: v_read() returned 0 before all bytes read\n");
      return bytes_read;
    }
		
    bytes_read += ret;
  }

  return bytes_read;
}

//initial branching of cases will happen here!
void tcp_handler(const char *packet, interface_t *inf, int received_bytes){

	struct iphdr *ipheader = malloc(sizeof(struct iphdr));
	(void)decapsulate_fromip(packet, &ipheader);
	tcphdr *tcpheader = (tcphdr *) malloc(TCPHDRSIZE);
	memcpy(tcpheader, packet+IPHDRSIZE, TCPHDRSIZE);
	
	tcp_ntoh(tcpheader);//necessary, is it though? (mani)
#ifdef DEBUG
    printf("\n******************** Received tcp packet **************************: \n");
#endif
	
  if (is_listening(tcpheader->destport) == NULL) {

#ifdef DEBUG
    printf(_YELLOW_"CASE 0 : No Listening socket, simply ignoring the SYN"_NORMAL_"\n");
#endif

		free(ipheader);
		free(tcpheader);
    return;
  }

  /* Lets see if we even are listening or not! */
  sockets_on_port *sop = get_sockets_on_port(tcpheader->destport);

  /********************* CASE 0: HANDSHAKE 1 *******************
  1. only SYN is set. possibilities :
    NOTE : make room for 2 uint32_t (IMPORTANT: uncast it from tcphdr)
  ******************************************************************/
  if(SYN(tcpheader->orf) && !ACK(tcpheader->orf)){

#ifdef DEBUG
    printf(_YELLOW_"CASE 1 : handshake (1), receieved SYN"_NORMAL_"\n");
    tcp_print_packet(tcpheader);
#endif

    void *tbq= realloc(tcpheader, TCPHDRSIZE + 2*SIZE32);
    memcpy(tbq+TCPHDRSIZE, &ipheader->saddr, SIZE32);
    memcpy(tbq+TCPHDRSIZE+SIZE32, &ipheader->daddr, SIZE32);
    NQ(sop->listening_socket->q, tbq);

		free(ipheader);
    return;
  } 

  /*  Get the associated socket   */
  socket_lookup_key *key = malloc(sizeof(socket_lookup_key));
  memset(key, 0, sizeof(socket_lookup_key));
  key->urport = tcpheader->sourceport;
  key->myport = tcpheader->destport;
  key->uraddr = ipheader->saddr;
  socket_t *so; 
  HASH_FIND(hh2, socket_table, &key->urport, keylen, so);
	free(key);
  
  if(so == NULL){

#ifdef DEBUG
    printf(_YELLOW_"Warning : non-request packet received from stranger"_NORMAL_"\n");
#endif
      free(tcpheader);
      free(ipheader);
      return;
  }

  /******************** Handshake 2 **************************
  SYN_SENT --> ESTABLISHED
  ************************************************************/
  if(SYN(tcpheader->orf) && ACK(tcpheader->orf) && (so->state == SYN_SENT)){

#ifdef DEBUG
    printf(_YELLOW_"\t CASE 2 : handshake (2), receieved SYN/ACK"_NORMAL_"\n");
#endif

    set_socketstate(so, ESTABLISHED);
    so->ackseq= ++(tcpheader->seqnum); 
    //so->adwindow = tcpheader->adwindow;
    tcp_send_handshake(ESTABLISHED, so);
		free(tcpheader);
		free(ipheader);
    return;
  }

  /**** Special CASE : Both close at the same time*************
  * A v_close() at the same time as B v_close()
  ************************************************************/
  else if (FIN(tcpheader->orf) && ACK((tcpheader->orf)) && (so->state == FIN_WAIT_1)) {

#ifdef DEBUG
    printf(_YELLOW_"CASE 3 : Both close at the same time"_NORMAL_"\n");
#endif

    set_socketstate(so, CLOSING);
    so->ackseq = tcpheader->seqnum+1;
    so->ackseq = tcpheader->ack_seq+1;
    tcp_send_handshake(CLOSING, so);

  }

  /*************** CASE 1 : FIN received *************
    a) current state = ESTABLISHED :
        -> change state to CLOSE WAIT
    b) current state = FIN_WAIT_2 :
        ->change state to TIME_WAIT
  ****************************************************/
  else if (FIN(tcpheader->orf)) {

#ifdef DEBUG
    printf(_YELLOW_"CASE 4 : FIN"_NORMAL_"\n");
#endif

    if (so->state == ESTABLISHED) {
      so->ackseq = tcpheader->seqnum+1;
      set_socketstate(so, CLOSE_WAIT);
      tcp_send_handshake(ACKNOWLEDGE, so);
    }
    else if (so->state == FIN_WAIT_2) {
      so->ackseq = tcpheader->seqnum+1;
      set_socketstate(so, TIME_WAIT);
      tcp_send_handshake(ACKNOWLEDGE, so);
			set_socketstate(so, CLOSED);
    }

  }

  /************** CASE 2 : ONLY ACK received and [state=FIN_WAIT_1] **************
    1. if socket in FIN_WAIT_1 state
      i)  change to FIN_WAIT_2, dont send anything, 
          wait for the other side to close.....
  ****************************************************/
  else if (ACK((tcpheader->orf)) && !SYN((tcpheader->orf)) && (so->state == FIN_WAIT_1)) {

#ifdef DEBUG
    printf(_YELLOW_"CASE 4 : ACK while we are FIN_WAIT_1"_NORMAL_"\n");
#endif

    set_socketstate(so, FIN_WAIT_2);
    tcpheader->seqnum = tcpheader->seqnum;
    
  }

  /************** CASE 3 : ONLY ACK received and [state=LAST_ACK] **************
    1. if socket in LAST_ACK state
      i)  change to CLOSED
  ****************************************************/
  else if (ACK((tcpheader->orf)) && !SYN((tcpheader->orf)) && (so->state == LAST_ACK)) {

#ifdef DEBUG
    printf(_YELLOW_"CASE 5 : ACK and we are LAST_ACK"_NORMAL_"\n");
#endif

    set_socketstate(so, CLOSED);
    tcpheader->seqnum = tcpheader->seqnum;
    
  }

  /********* CASE 3 : ONLY ACK from simultanous close() [state=CLOSING] ****
    1. if socket in LAST_ACK state
      i)  change to CLOSED
      ii) simultanous closing waiting for ack
      iii) 2MSL timeout from TIME_WAIT -> CLOSED
  ***************************************************************************/
  else if (ACK((tcpheader->orf)) && !SYN((tcpheader->orf)) && (so->state == CLOSING)) {

#ifdef DEBUG
    printf(_YELLOW_"CASE 6 : ACK and we are CLOSING"_NORMAL_"\n");
#endif

    set_socketstate(so, TIME_WAIT);
    tcpheader->seqnum = tcpheader->seqnum;
    
  }

	else {
		#ifdef DEBUG
    printf(_YELLOW_"CASE 7 : ACK general"_NORMAL_"\n");
		#endif

		//if anything arrives beyond the third grip, ESTABLISHED
		if(so->state == SYN_RCVD){
			set_socketstate(so, ESTABLISHED);
			free(ipheader);
			free(tcpheader);
			return;
		}

		//SLDING WINDOW GOES HERE!
		if(ACK(tcpheader->orf)){

			#ifdef DEBUG
			printf("\nSLIDING WINDOW CALLED-----------------------\n");
			#endif

			seg_t *el, *temp;
			int count;
			sendw_t *sendw = so->sendw;

			//if this is a novel ack
			pthread_mutex_lock(&sendw->lock);
			if(tcpheader->ack_seq != sendw->hack){

				//store highest ACK for fast dequeuing from retransmission queue
				sendw->hack = tcpheader->ack_seq;
				//store adwindow of the corresponding receiving window
				sendw->adwindow = tcpheader->adwindow;

				//store ack in ackhistory table for RTT calculation
				ack_t *nack = malloc(sizeof(ack_t));
				nack->ackseq= tcpheader->ack_seq;
				gettimeofday(&nack->tstamp, NULL);
				HASH_ADD(hh, sendw->ackhistory, ackseq, sizeof(uint32_t), nack);

				//show newly acked segments
				#ifdef DEBUG
				printf("TCP: ack for %d arrived\n", tcpheader->ack_seq);
				#endif

				/*  
				printf(_WHITE_"Retransmission Queue Contents:\n"_NORMAL_);
				DL_FOREACH(sendw->retrans_q_head, el){
					printf(_WHITE_"*segment: [%d ---%d bytes--- %d]"_NORMAL_, el->seqnum, el->seglen,
						el->seqnum+el->seglen-1);
					if(el->seqnum < tcpheader->ack_seq) printf(_GREEN_"NACKED"_NORMAL_);
					printf("\n");
				} */
			} 

			pthread_mutex_unlock(&sendw->lock);

			int payloadsize = ipheader->tot_len -IPHDRSIZE - TCPHDRSIZE;
				
			//If there is new data in the packet
			if(payloadsize){
				#ifdef DEBUG
				printf("Packet contains data:\n");
				printf(_WHITE_"*segment: [%d ---(%d bytes)--- %d]\n"_NORMAL_, tcpheader->seqnum,
				payloadsize, (tcpheader->seqnum + payloadsize - 1) % MAXSEQ);
				#endif
				recvw_t *rwin = so->recvw;
					//we don't have space for more data
				if(CB_FULL(rwin->buf)){
					#ifdef DEBUG
					printf(_BRED_"\tTCP: recv window full\n"_NORMAL_);
					#endif
					free(ipheader);
					free(tcpheader);
					return;
				}

				//if we send the right adwindow of CB_GETCAP - size of OOr queue,
				//OOr chains will never overflow
				int cap = CB_GETCAP(rwin->buf);
				//if this segment is what we are expecting
				if(tcpheader->seqnum == so->ackseq){
					#ifdef DEBUG 
					printf(_GREEN_"TCP: SEGMENT IN ORDER\n"_NORMAL_);
					#endif
					CB_WRITE(rwin->buf, packet+IPHDRSIZE+TCPHDRSIZE, MIN(cap, payloadsize));
					so->ackseq = (so->ackseq + payloadsize) % MAXSEQ; //TODO wrap
					DL_COUNT(rwin->oor_q_head, el, count);
					//Any adjacent packets previously received out of order?
					if(count){
						uint32_t adjseq = (tcpheader->seqnum + payloadsize) % MAXSEQ; //TODO wrap

						while(1){
							el = NULL;
							DL_SEARCH_SCALAR(rwin->oor_q_head, el, seqnum, adjseq);
								if(el==NULL) break; //adjacent chain broken!
							//adjacent chain continues!
							CB_WRITE(rwin->buf, el->data,
								MIN(el->seglen, cap - payloadsize));
							so->ackseq  = (so->ackseq + el->seglen) % MAXSEQ; //TODO wrap
							adjseq = (el->seqnum + el->seglen) % MAXSEQ; //TODO wrap
								//get rid of it from the OOr q
							rwin->oor_q_size -= el->seglen;
							DL_DELETE(rwin->oor_q_head, el);
						}
					}

				} else {
					
					if(so->ackseq + CB_GETCAP(rwin->buf) < tcpheader->seqnum || 
						tcpheader->seqnum < so->ackseq){
						#ifdef DEBUG
						printf(_YELLOW_"TCP: PACKET IRRELEVANT (OUT OF WINDOW OR REDUNDANT)\n"_NORMAL_);
						#endif
					}
					else {
						#ifdef DEBUG
						printf(_RED_"TCP: OUT OF ORDER (BUT RELEVANT)\n"_NORMAL_);
						#endif
						//check if this out of order packet has already been received
						el = NULL;
						DL_SEARCH_SCALAR(rwin->oor_q_head, el, seqnum, tcpheader->seqnum);
						if(el==NULL){
							el = malloc(sizeof(seg_t));
							DL_APPEND(rwin->oor_q_head, el);
							rwin->oor_q_size+=payloadsize;
							el->seqnum = tcpheader->seqnum;
							el->seglen = payloadsize;
							unsigned char *payload = malloc(payloadsize);
							memcpy(payload, packet+IPHDRSIZE+TCPHDRSIZE,payloadsize);
							el->data = payload;
							DL_SORT(rwin->oor_q_head, seqcmp);
						}
					}
				}

				//time to send ACK -- ACK or a duplicate ACK
				/*
				tcphdr *ack = tcp_craft_ack(so);	
				tcp_hton(ack);
				send_tcp(so, (char *)ack, TCPHDRSIZE);
				free(ack); */
				tcp_send_handshake(ESTABLISHED, so);
				free(tcpheader);
				free(ipheader);
				#ifdef DEBUG
				printf("sending an ACK for %d\n", so->ackseq);
				printf("%d bytes left on the buffer\n", 
					CB_GETCAP(so->recvw->buf) - so->recvw->oor_q_size);
				printf("---------------------------------------\n");
				#endif 
			} else {
				#ifdef DEBUG
				printf("---------------------------------------\n");
				#endif
			}
		}
	}
  return;
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
    fprintf(stderr, _RED_"v_connect() error: %s"_NORMAL_"\n", strerror(-ret));
    return;
  }
  printf("v_connect() returned %d\n", ret);

  return;
}

/******************************* Send Command ******************
 PROBLEMS : 
    1. 
****************************************************************/
void send_cmd(const char *line) {

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
  	bytes_read = v_read_all(socket, buffer, bytes_requested);
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


int seqcmp(seg_t *seq1, seg_t *seq2){
	return (int) seq1->seqnum - (int) seq2->seqnum;
}

void regular_update(){
	
	rtu_routing_entry *entry, *temp;
	char xx[INET_ADDRSTRLEN];
	time_t now = time(NULL);

	if( (now - lastRIPupdate) > 2){
		broadcast_rip_table();
		lastRIPupdate = now;
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

	regular_update();
	//decrement_ttl();

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


void rip_handler(const char *packet, interface_t *i, int nothing){
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
			//print_routes();
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



/*
 * =====================================================================================
 *
 *       Filename:  pseudo_1node.c
 *
 *    Description:  Pseudocode for TCP- Up to getting 1 node up
 *
 *        Version:  1.0
 *        Created:  10/26/2013 07:23:01 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


A new format is required for TCP pseudocode.


[SCENARIO: THREE WAY HANDSHAKE]
A (ip: 57) <-> B (ip: 157)

	on B: accept 2013
		in void accept_cmd(const char *line)
		//create a listening socket and a listening thread
			accept_cmd("2013")
			"s = v_socket()"
			any_addr.s_addr = 0;
			"v_bind(s, any_addr, htons(2013))"
			"v_listen(s)"
			pthread_create(accept_thr_func, (void *) s);
		in void *accept_thr_func(void *arg)
			while(1)
				"v_accept(s, NULL)"
	on A: connect 157 2013
		in void connect_cmd(const char *line)
			inet_aton(ip_string, &ip_addr)
			s = v_socket()
			"v_connect(s, ip_addr, htons(port))"



$GLOBAL VARIABLE DEFINITIONS
	

$STRUCT DEFINITIONS
	//socket representation
	typedef struct socket_t{
		int sock_id;
		int sock_type;
		int sock_port;
		//TODO make a queue
	} socket_t;


	//file descriptor table
	/*
	tpyedef struct fd_table_entry{
		int fd_id;
		struct socket_t *socket;
	} fd_table_entry;
	*/

$FUNCTION DEFINITIONS
	int fd_table_add(fd_table_entry *newentry)
		-adds a new entry for a socket in the global fd_table
	socket_t *fd_table_lookup(int socket)
		-looks up a socket with the id and returns a pointer to it

	int v_socket():
		-equivalent to UNIX socket(PF_INET, SOCK_STREAM, 0)
		*creates a socket
			socket_t *newsocket = malloc(sizeof(socket_t))
			newsocket->sock_id = "maxfd" + 1
			newsocket->sock_type = STREAM
			newsocket->sock_port = 0 (for now)
		*registers the socket in the file descriptor table
			"fd_table_add(newsocket)"
		*returns the id of the socket
			return newentry->socket

	int v_bind(int socket, struct in_addr *addr, uint16_t port)
		-why bind? because when a TCP packet comes in, TCP needs to be able
		to queue it in the right socket
			(IP passes the packet to "TCP", it reads the destination port,
			queues the packet for the right socket)
		*binds the socket to a port
			socket_t *so = "fd_table_lookup(socket)"
			so->sock_port = port

	int v_listen(int socket)
		*if not already bound, v_bind() the socket to a random port number
			struct in_addr any_addr
			any_addr.s_addr = 0
			socket_t *so = "fd_table_lookup(socket)"
			if(!so->sock_port) v_bind(socket, any_addr, "random number")
		*move socket into "listen state"
			-tell "TCP" that this socket is in the listening state
			->when a connection packet comes in for this port, "TCP"
			will queue 

		*edge case: 

	int v_accept(int socket, struct in_addr *node)
		//*edge case: is this even bound? is this even listening?
		*checks whether there is a pending request for this socket
			socket_t *so = sockets_lookup(socket);
			if(so->request == NULL) return -1
		*make sense out of the packet passed
		*populate struct in_addr passed in with info from struct iphdr
		*using demux key (sport, dport, saddr, daddr), identify the connection
			-> if this connection does not exist, make a new one and initiate handshak
			-> if this packet correctly concludes a three-way handshake, shift the
				connection's state to ESTABLISHED and finish.
			-> "EDGE CASE" if this connection already exists, deal with it
		

	int v_connect(int socket, struct in_addr *node, int port)
		*pack a struct tcphdr packet with
		
	

$SETUP
	setup interfaces
	initialize routing table
	*initialize file descriptor system
$EVENT LOOP
	

$EXIT







/*
 * =====================================================================================
 *
 *       Filename:  pseudo_2node.c
 *
 *    Description:  pseudocode to get two nodes up, communicating according to the protocol
 *
 *        Version:  1.0
 *        Created:  10/04/2013 01:15:32 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */



<-TODO->
*observe MTU of 1400
*where to ntoh
*sizeof macros
*how to deal with when there are too much data typed in


$DEFINITIONS
	Global Variables
		#list_t *interfaces
		list_t *links <-CONCERN->We probably do not need this.
		#int interface_count
		#fd_set masterfds
		#int maxfd
	Structs
		#struct interface_t{
			int id;
			int sockfd;
			struct sockaddr *soruceaddr;
			struct sockaddr *destaddr;
			uint32_t sourcevip;<-WARNING-> vips are stored with ntohl() applied
			uint32_t destvip; 		reverse the order for IP packet
			bool status;	
		}

		#struct rtu_routing_entry{
			uint32_t cost;
			uint32_t addr;
			uint32_t nexthop;
			bool local;
		}
	Functions
		#int setup_interface(char *filename)
			-initializes interface list
			-for each line in the lnx file, make an interface and add to the list
			-<-WARNING->Looks like using memcpy to copy sockaddr of source and destination
			has worked out. But if sendto() or recvfrom() gives you problem, this is your
			first bet.
		#int get_socket(uint16_t portnum, struct addrinfo **source, int type)
		#int get_addr(uint16_t portnum, struct addrinfo **addr, int type, int local)
			-gets the address of both "local" ports and "remote" ports.
			-"remote" addresses are stored inside interface and used for 
			sending packets later
		#int init_routing_table();
		#void print_interfaces()
		#void print_routes()
		#int request_routing_info(interface_t *port)
		#int encapsulate_inip(uint32_t src_vip, uint32_t dest_vip, uint8_t protocol, void *data, char **packet)
		#int send_ip(interface_t *inf, char *packet, int packetsize)
		#id_ip_packet(char *buf, struct iphdr **ipheader)
		*get_nexthop
		*up_interface
		*down_interface
		*init_routing_table
		*routing_table_add
		*find_route_entry

$SETUP
	#setup file descriptor sets(readfds and masterfds)
	#setup interfaces
	#set up routing table with own interfaces
		#init_routin_table: make a list_t filled with all the interfaces
	#send out RIP request packet to own interfaces
		#craft the RIP request packet -> request_routing_info()
		#enclose the RIP packet inside the IP packet ->encapsulate_inip()
		#send it to every interface -> send_ip()

$EVENT LOOP
	*select()
	*read commands FD_ISSET(0, &readfds)
		#"interfaces"
		#"routes"
		*"send vip() proto(always plain IP) string"
			*get_nexthop()
			*encapsulate_inip()
			*send_ip()
	*recvfrom() packets from UDP sockets
		#if local delivery
			#if RIP
				*update routing table
				*if it's a new guy, respond with your own routing table
			#if IP
				*print out payload
		#if to be forwarded
			*get_nexthop()
			*send_ip()
$EXIT
	free interface_t list
	close sockets






[Design for sending of IP, RIP and higher protocol packages]
Cases to design for
	1. RIP to everyone
		make the RIP packet
		encapsulate it in an IP packet
		send it to an interface
		*request_routing_info(interface_t *port)
			*encapsulate_inip()
			*send_ip()
	2. RIP to specific node
		make the RIP packet
		encapsulate it in an IP packet
		send it to an interface
		*respond_routing_info(interface_t *port)
			*encapsulate_inip()
			*send_ip()
	3. Plain IP to specific node
		get the data
		consult routing table
		encapsulate it in an IP packet
		send the IP packet to an interface
		*interface_t *get_nexthop(uint32_t dest_vip): takes in VIP of the final destination, returns the interface
			of the next hop
		*encapsulate_inip(uint32_t src_vip, uint32_t dest_vip, int protocol)
		*send_ip()
	4. Relaying packet
		look at the IP header
		if for our interface, decapsulate
		if not for our interface, get nexthop() and send to the interface()
	5. Fragmentation
		if there is MTU difference
			get nexthop
			encapsulate_inip(): 
			send_ip()
	6. Other Higher level protocols (TCP)
		get the data

Information required to craft and send a packet
	1. Departing interface
		two ways to get this info
		1. consult the routing table
		2. send it to everyone (already know)
	2. The packet contents
		1. protocol: 


























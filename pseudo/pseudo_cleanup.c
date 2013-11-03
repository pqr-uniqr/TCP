
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


//net layer macros
#define LOCALDELIVERY 	1
#define FORWARD 	0

//interface macros
#define UP 		1
#define DOWN 		0
#define OWN_COST	0

//net layer macros
#define REQUEST 	1
#define RESPONSE	2

//link layer macro
#define MTU		1400

//fragmentation (net layer)
#define NOOFFSET	200

//interface macro
#define LOCAL		1

//this has to be known to the main function
#define IP 0
#define RIP 200
#define REFRESH_TIME	15
#define IPHDRSIZE sizeof(struct iphdr)

$DEPENDENCIES (for cleaning up IP)

	#interface.h:
		struct interface_t
	#iputil.h:
		encapsulate_inip()
		id_ip_packet()
		"print_ip_packet(struct *iphdr)"

	#linklayer.h:
		get_socket()
		get_addr()
		setup_interface()
		up_interface()
		down_interface()
		set_mtu()
		"free_interface()"

	#netlayer.h:
		"net_register_handler()"
		send_ip()
	#rip.h:
		struct rip_entry
		struct rip_packet
	route.h:
		struct rtr_routing_entry
		interface_t *route_lookup(uint32_t dest)
			-"not being used"
		init_routing_table()
		int route_table_add(uint32_t nexthop, uint32_t dest, int cost, int local)
			-"route_table_update is not using this"
		routing_table_send_response()
		route_table_update()
		routing_table_refresh_entries
			-"not being used"
		routing_table_send_update()
	*util.h:		
		print_routes()
		print_interface()
		routing_table_print_packet()
	//TODO make a new copy of IP and clean up based on this!






$DEFINITION
	for IP node select():
		fd_set masterfds
		int maxfd
	for Interface list:
		list_t *interfaces
		//use hash table instead?
	for routing table:
		rtu_routing_entry routing_table
	for Fragmentation:
		frag_list *piecekeeper
		//do we need to keep this for TCP?
		
$SETUP
	*parse cmdline args:
		argv[1]: lnxfile
		*argv[2]: droprate
	#setup_interface()
	#init_routing_table()
	*(TCP)Start listening on port 20: setup_passive_TCP()

$EVENT LOOP
	*RIP regular update
	*Decrement TTL for every RIP entry
	*select()
	*for every interface:
		if(sockfd is set)
		#1-RIP
		#2-IP
		*3-TCP
			
	
	

$EXIT








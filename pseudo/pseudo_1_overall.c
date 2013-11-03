




----------------------------------------------------------------------------------------------------------------------------
$DEFINITIONS
	*Functions
		ssize_t forward(interface_t *interface, char *data)
			-usage: command send, received packet is to be sent again
			*enforce MTU of 1400 bytes here:

		ssize_t receive_packet(interface_t *interface, char *buf)
			<-CONCERN->?char * or char **
			bytes = recvfrom(interface->udp_sockfd, buffer of size 64k (recvbuf), 64k, 0(options);

		list_t *setup_interface(char *filename)
			<-PSEUDO-> Usage: setup_interface(arg[1])
				struct list_t *link_list_head= parse_links(filename)
				struct node_t *ln
				for(ln=list_of_links->head; ln!=NULL;ln=ln->next)

		int inspect_ip_header(char *packet);
			<-CONCERN-> packet: the whole packet or just the 5-word header
			<-EXTRACREDIT-> check if ident field is empty
	
		void net_register_handler(uint8_t protocol_num, handler_t handler)

	*Structs
		typedef struct
			int udp_sockfd
			int port_no
			int up
			struct ip *dest_addr
			<-CONCERN->What exactly do we need for ip
		interface_t 

	*Macros
		#define RECVBUFSIZE 65536
		#define LOCALDELIVERY 1
		#define FORWARD 0


----------------------------------------------------------------------------------------------------------------------------
$SETUP
	*declare variables
		list_t *list_of_interfaces
		char *recvbuf = malloc(RECVBUFSIZE);
		interface_t *interface;
		node_t *curr;
		struct ip empty_ip_header;
		
	*set up link layer "interfaces"
		<-MODULE->list_of_interfaces = setup_interface(argv[1]);

	*register handlers for protocol No. 200 (RIP) and protocol NO. 0 (test)
		<-MODULE->net_register_handler(200,(*handler_t)&rip_handler)
		<-QUESTION-> Is this how I'd use it

	*set up for select() call


	*Updating 
	*send routing tables & etc to neighbors

98.73893: Bringing up 10.116.89.15798.73895: ->10.10.168.73 : MAKE SOCKET
98.73899: Creating receive thread on interface from 10.116.89.15798.73901:  to 10.10.168.73: 


98.73905: route: updating routing table with own interfaces: 
98.73908: route: Found new route to 10.116.89.157, cost=0.
Node all set [ CTRL-D / CTRL-C to exit ]
	for each interface in list_of_interfaces:
		route_update(interface -> vip)


98.73914: route: sending out requests to all our interfaces
	
98.73921: route: Regular update.
98.73923: Sending routing table to everyone.
98.73923: Sending routing table to interface 10.116.89.157
98.73925: Sending update to 10.10.168.73
98.73926: route-table has size 1
98.73927:     cost=0, fwd=10.116.89.157
98.73929: route: updating routing table with own interfaces
98.73930: route: Refreshing entry for 10.116.89.157, cost still 0.


----------------------------------------------------------------------------------------------------------------------------
$EVENT LOOP
	*select() for async polling on FDs 

	*read() commands
		*trivial cases
		*"interface, routes"
			for interface in list_of_interfaces
				print info
			for entry in routing table
				print info
		*down int, up int
			<-QUESTION->what is the int--what identifies an interface?
			<-QUESTION->How to bring an interface "down" (or "up")

		*send vip, proto, string
			struct ip newaddress
			newaddress.ip = vip newaddress.proto = proto 
			<-MODULE-> forward(newaddress, string) 
			<-CONCERN-> Edge case: what if vip is one of my own interfaces

	*read packets and deal with it
		for curr = list_of_interfaces;curr !=NULL;curr = curr->next
			interface = (interface_t *) curr->data
			if FD_ISSET(interface->udp_sockfd)

				<-MODULE->bytes = receive_packet(interface, recvbuf);

				if(bytes == -1)
					->system broke
					->notify and break() away into safe exit!

				if(bytes == 0)
					->connection terminated -> node down!
					->you probably want to tell the routing module about this
					->continue()
						<-CONCERN->but should I not wait for the forwarding table to be updated?
							that is, before I can continue to the next interface-- this might
							support select() over threads

				<-MODULE->decision = inspect_ip_header(recvbuf, 64k, &emtpy_ip_header)
				
				if(decision == -1)
					->system broke
					->notify and break() away into safe exit!

				if(decision == LOCALDELIVERY)
					->the packet was for one of our interfaces
					-><-QUESTION->how to trigger handler?

				if(decision == FORWARD)
					->the packet is not for one of our interfaces
					-><-EXTRACREDIT-> 
					-><-MODULE->forward(&empty_ip_header)

	*quick chat with the routing module: "Do I need to send out some RIP packets?"
		
						
----------------------------------------------------------------------------------------------------------------------------
$Exit 
	free_links()
	free the buffer used for recvfrom()


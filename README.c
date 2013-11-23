README for TCP -author: Pete Kim, Mani Askari

Hello, most of the important information about design decisions are in pseudo/pseudo_*

--but since they were written mostly for internal use, let us first give you an outline



[HOW TO USE]
PRINTFS
	if you want to get rid of the printf()'s for a more accurate performance measure,
	find "#define DEBUG" in both FILE: common.h and FILE: node.c and //TODO UNCOMMENT them
	*This still leaves some printfs on, for minimum debugging


DEPENDENCY TREE & MAKEFILE
	---------------------
					node.* 
						^
					v_api.*
						^
			socket_table.*
						^
				srwindow.*
						^
					tcputil.*
						^
				interfaces.*
				^				^
			rip.*		iputil.*
	---------------------

Above is the dependency graph (a simple tree). Run "make" to compile and "make clean"
to clean up objective and executable files


[FEATURES]

#connection timeout feature

#correct checksum for ACK, data and handshake

#packet-wide ntoh and hton 

#sequnce number wrap around

#SRTT calculation

#retransmission queue

#keeps a list of out of order packets (that are within the window)

#connection teardown

#persistent connection request

[PRINCIPLES]
Some of the design principles we established and followed

PRINCIPLE: Whenever possible, don't pass malloc-ed data down or up
PRINCIPLE: SOCKET SEQUENCE/ACKSEQ NUMBER UPDATE
	-a socket's acknowledge number is updated when packet arrives (socket->ackseq)
	-sequence number (next byte to be sent) is updated when packet goes out (socket->seqnum)
PRINCIPLE: Sender must limit the amount of unacked bytes to adwindow at any point

C = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_REENTRANT -D_XOPEN_SOURCE=500
LDFLAGS = -pthread

UTIL= csupport/list.c csupport/dbg.c csupport/ipsum.c csupport/parselinks.c

#source code
SRC=$(wildcard *.c)
#headers (no need to be included)
HDR=$(wildcard *.h)
#will be the prerequisite
OBJ=$(SRC:.c=.o) $(UTIL:.c=.o)

node: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)
	@echo "make Complete."

clean:
	rm node $(OBJ)
	@echo "$(OBJ) removed!"

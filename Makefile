CC      = gcc
CFLAGS  = -Wall -Wextra -std=gnu11 -O2

all: loadbalancer server client

loadbalancer: loadbalancer.c protocol.c protocol.h
	$(CC) $(CFLAGS) -o $@ loadbalancer.c protocol.c

server: server.c protocol.c protocol.h
	$(CC) $(CFLAGS) -o $@ server.c protocol.c

client: client.c protocol.c protocol.h
	$(CC) $(CFLAGS) -o $@ client.c protocol.c

clean:
	rm -f loadbalancer server client

.PHONY: all clean

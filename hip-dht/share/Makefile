CC=gcc
CFLAGS=
XDR=rpcgen
XDRCONFIG=rpcif.x

all: rpcstub compile client
rpcstub:
	$(XDR) -h $(XDRCONFIG) > rpcif.h
	$(XDR) -l $(XDRCONFIG) > rpcif_client.c
	$(XDR) -c $(XDRCONFIG) > rpcif_xdr.c
compile:
	$(CC) $(CFLAGS) -c rpcif_client.c
	$(CC) $(CFLAGS) -c rpcif_xdr.c
	$(CC) $(CFLAGS) -c client.c

client:
	$(CC) $(CFLAGS) client.o rpcif_xdr.o rpcif_client.o -o client

clean:
	rm -f *.o
	rm -f rpcif.h rpcif_client.c rpcif_xdr.c
	rm -f test client


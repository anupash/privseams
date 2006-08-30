AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags) -DHIP_UNITTEST_MODE -L$(HIPL_LIBINET6_LIB)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

XDR=rpcgen
XDRCONFIG=rpcif.x

EXTRA_DIST = rpcif.x
CLEANFILES = rpcif.h rpcif_client.c rpcif_xdr.c

bin_PROGRAMS = client
client_SOURCES =  rpcif_client.c rpcif_xdr.c client.c

rpcif.h:
	$(XDR) -h $(XDRCONFIG) > rpcif.h
rpcif_client.c:
	$(XDR) -l $(XDRCONFIG) > rpcif_client.c
rpcif_xdr.c:
	$(XDR) -c $(XDRCONFIG) > rpcif_xdr.c

client.c: rpcif.h
opendht_interface.c: rpcif.h
rpcif_client.c: rpcif.h


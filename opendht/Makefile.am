AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags) -DHIP_UNITTEST_MODE -L$(HIPL_LIBINET6_LIB)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

EXTRA_DIST = rpcif.x

XDR=rpcgen
XDRCONFIG=rpcif.x

if HIP_OPENDHT

CLEANFILES = rpcif.h rpcif_client.c rpcif_xdr.c

lib_LTLIBRARIES = libdhtresolver.la libdhttracker.la
libdhtresolver_la_SOURCES  = resolver.c opendht_interface.c rpcif_client.c rpcif_xdr.c
libdhttracker_la_SOURCES = tracker.c

bin_PROGRAMS =  client client-teststub tracker-teststub dht-dnsd

client_SOURCES =  client.c
client_teststub_SOURCES = client-teststub.c
tracker_teststub_SOURCES = tracker-teststub.c
dht_dnsd_SOURCES = conf.c base64.c dns.c hex.c sha.c validator.c

LDADD = .libs/libdhttracker.a .libs/libdhtresolver.a ../libinet6/.libs/libinet6.a

../libinet6/.libs/libinet6.a:
	$(MAKE) -C $(HIPL)/libinet6

rpcif.h:
	$(XDR) -h $(XDRCONFIG) > rpcif.h
rpcif_client.c:
	$(XDR) -l $(XDRCONFIG) > rpcif_client.c
rpcif_xdr.c:
	$(XDR) -c $(XDRCONFIG) > rpcif_xdr.c

client.c: rpcif.h
opendht_interface.c: rpcif.h
# According to Tao, enabling this gives an error:
# opendht/Makefile.am:33: rpcif_client.c multiply defined in condition
#rpcif_client.c: rpcif.h

else

# Workaround for "make dist" to succeed;
# the generatable c files are problematic.
rpcif_client.c:
	touch  rpcif_client.c
rpcif_xdr.c:
	touch  rpcif_xdr.c

endif

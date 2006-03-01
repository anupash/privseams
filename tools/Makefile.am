AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS = $(hipl_common_cflags) -L$(HIPL_LIBINET6_LIB)

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

include_HEADERS = hipconf.h

# OpenDHT
INCLUDES += -I../hip-dht/tracker -I../hip-dht/dnsd -I../hip-dht/clientlib

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
LDADD    = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a

LDFLAGS = -lcrypto

sbin_PROGRAMS = hipconf
hipconf_SOURCES = hipconf.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

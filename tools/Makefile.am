AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS = -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL) $(GDB_CFLAG)
CFLAGS += -L$(HIPL_LIBINET6_LIB) -I$(HIPL_HIPD)
CFLAGS += -I$(HIPL_LIBINET6) -I$(HIPL_LIBHIPTOOL)

include_HEADERS = hipconf.h

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

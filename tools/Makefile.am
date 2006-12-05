AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS = $(hipl_common_cflags) -L$(HIPL_LIBINET6_LIB)

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

include_HEADERS = hipconftool.h

if HIP_OPENDHT
 INCLUDES += -I../hip-dht/tracker -I../hip-dht/dnsd -I../hip-dht/clientlib
endif
if HIP_HI3
 INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
endif

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
if HIP_OPENDHT
  LDADD    = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a 
#../opendht/.libs/libdhtresolver.a
else
  LDADD    = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a 
endif

LDFLAGS = -lcrypto

sbin_PROGRAMS = hipconf
hipconf_SOURCES = hipconftool.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#

CFLAGS = $(hipl_common_cflags) $(HIPL_XMLI) # -L$(HIPL_LIBINET6_LIB)

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

include_HEADERS = hipconftool.h

dist_bin_SCRIPTS =  myasn.py parse-key-3.py wget-dht-servers.sh
dist_bin_SCRIPTS += dnsproxy.py pyip6.py util.py hosts.py
dist_bin_SCRIPTS += DNS/Base.py DNS/Class.py DNS/Lib.py 
dist_bin_SCRIPTS += DNS/Opcode.py DNS/Status.py DNS/Type.py
dist_bin_SCRIPTS += DNS/__init__.py DNS/lazy.py DNS/pyip6.py DNS/win32dns.py

LDFLAGS = -lcrypto $(HIP_XMLL)

INCLUDES += -I../opendht

if HIP_HI3
 INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
endif

LDADD=
if HIP_OPPORTUNISTIC
  LDADD += ../libopphip/.libs/libopphip.a
endif

LDADD += ../libinet6/.libs/libinet6.a
if HIP_CORPORATE
  LDADD += -lhiptool
else
  LDADD += ../libhiptool/.libs/libhiptool.a
endif

LDADD += ../opendht/.libs/libhipopendht.a

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below

sbin_PROGRAMS = hipconf
hipconf_SOURCES = hipconftool.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

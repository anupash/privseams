AUTOMAKE_OPTIONS = foreign

EXTRA_DIST =  DNS/Base.py DNS/Lib.py DNS/Type.py DNS/Class.py 
EXTRA_DIST += DNS/Opcode.py DNS/win32dns.py DNS/__init__.py
EXTRA_DIST += DNS/pyip6.py DNS/lazy.py DNS/Status.py

dist_sbin_SCRIPTS = dnsproxy.py myasn.py pyip6.py hosts.py parse-key-3.py
dist_sbin_SCRIPTS  += util.py

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#

CFLAGS = $(hipl_common_cflags) # -L$(HIPL_LIBINET6_LIB)

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

include_HEADERS = hipconftool.h

LDFLAGS = -lcrypto $(HIP_XMLL)

if HIP_OPENDHT
  INCLUDES += -I../opendht
endif

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

if HIP_OPENDHT
  LDADD += ../opendht/.libs/libhipopendht.a
endif

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below

sbin_PROGRAMS = hipconf
hipconf_SOURCES = hipconftool.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

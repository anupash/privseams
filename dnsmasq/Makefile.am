AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#

CFLAGS = $(hipl_common_cflags) -L$(HIPL_LIBINET6_LIB) -DLOCALEDIR=\"$(prefix)/share/locale\"

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

include_HEADERS = config.h dnsmasq.h

LDFLAGS = -lcrypto

LDADD = ../libinet6/.libs/libinet6.a
if HIP_CORPORATE
  LDADD += -lhiptool
else
  LDADD += ../libhiptool/.libs/libhiptool.a
endif

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below

sbin_PROGRAMS = dnsmasq
dnsmasq_SOURCES = cache.c rfc1035.c util.c option.c forward.c isc.c network.c \
                  dnsmasq.c dhcp.c lease.c rfc2131.c netlink.c dbus.o bpf.c \
                  helper.c tftp.c log.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

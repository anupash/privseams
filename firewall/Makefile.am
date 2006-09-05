AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.

CFLAGS = $(hipl_common_cflags) -I/usr/include/libipq/  -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
CFLAGS += `pkg-config --cflags --libs glib-2.0` 
CFLAGS += `pkg-config --cflags --libs gthread-2.0`

include_HEADERS = firewall.h conntrack.h rule_management.h helpers.h
INCLUDES = $(hipl_common_include_paths)

if HIP_FIREWALL

sbin_PROGRAMS = firewall

firewall_SOURCES = firewall.c conntrack.c rule_management.c helpers.c

firewall_LDADD = /usr/lib/libipq.a ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a

endif

tags:
	etags $(firewall_SOURCES) $(include_HEADERS)

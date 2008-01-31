AUTOMAKE_OPTIONS = foreign

#EXTRA_DIST = hip-fw-mi-svn-20060226.tar.gz

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.

CFLAGS = $(hipl_common_cflags) -I/usr/include/libipq/  -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
CFLAGS += `pkg-config --cflags --libs glib-2.0` 
CFLAGS += `pkg-config --cflags --libs gthread-2.0`

include_HEADERS = firewall.h conntrack.h rule_management.h helpers.h firewall_control.h esp_decrypt.h firewall_defines.h midauth.h
INCLUDES = $(hipl_common_include_paths)

if HIP_FIREWALL

sbin_PROGRAMS = firewall

firewall_SOURCES = firewall.c conntrack.c rule_management.c helpers.c firewall_control.c esp_decrypt.c midauth.c

firewall_LDADD = /usr/lib/libipq.a ../libinet6/.libs/libinet6.a
if HIP_CORPORATE
  firewall_LDADD += -lhiptool
else
  firewall_LDADD += ../libhiptool/.libs/libhiptool.a
endif

if HIP_HI3
 INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
 firewall_LDADD += ../i3/i3_client/libi3client.a ../i3/i3/libi3.a ../i3/utils/libutils.a ../i3/aeshash/libaes.a -lpthread
endif

endif

tags:
	etags $(firewall_SOURCES) $(include_HEADERS)

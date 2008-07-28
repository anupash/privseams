AUTOMAKE_OPTIONS = foreign

#EXTRA_DIST = hip-fw-mi-svn-20060226.tar.gz

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.

CFLAGS = $(hipl_common_cflags) -I/usr/include/libipq/  -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
#CFLAGS += `pkg-config --cflags --libs glib-2.0` 
#CFLAGS += `pkg-config --cflags --libs gthread-2.0`
CFLAGS += `pkg-config --cflags`

include_HEADERS =  firewall.h conntrack.h rule_management.h helpers.h firewall_control.h hslist.h common_types.h
include_HEADERS += esp_decrypt.h firewall_defines.h proxydb.h conndb.h esp_decrypt.h dlist.h
include_HEADERS += user_ipsec.h user_ipsec_esp.h user_ipsec_sadb.h esp_prot.h
include_HEADERS += proxy.h opptcp.h firewalldb.h lsi.h
include_HEADERS += midauth.h pisa.h

INCLUDES = $(hipl_common_include_paths)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

if HIP_FIREWALL

sbin_PROGRAMS = hipfw

hipfw_SOURCES = firewall.c conntrack.c rule_management.c helpers.c firewall_control.c esp_decrypt.c proxydb.c conndb.c dlist.c hslist.c
hipfw_SOURCES += user_ipsec.c user_ipsec_esp.c user_ipsec_sadb.c esp_prot.c
hipfw_SOURCES += proxy.c opptcp.c firewalldb.c lsi.c
hipfw_SOURCES += midauth.c pisa.c

hipfw_LDADD = -lipq ../libinet6/.libs/libinet6.a
if HIP_CORPORATE
  hipfw_LDADD += -lhiptool
else
  hipfw_LDADD += ../libhiptool/.libs/libhiptool.a
endif

if HIP_PERFORMANCE
  hipfw_LDADD += ../performance/.libs/libperformance.a
endif

if HIP_HI3
 INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
 hipfw_LDADD += ../i3/i3_client/libi3client.a ../i3/i3/libi3.a ../i3/utils/libutils.a ../i3/aeshash/libaes.a -lpthread
endif

endif

tags:
	etags $(hipfw_SOURCES) $(include_HEADERS)

AUTOMAKE_OPTIONS = foreign

#EXTRA_DIST = hip-fw-mi-svn-20060226.tar.gz

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.

CFLAGS = $(hipl_common_cflags) -I/usr/include/libipq/ 
LDFLAGS = -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPCORE_LIB)
# -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
#CFLAGS += `pkg-config --cflags --libs glib-2.0` 
#CFLAGS += `pkg-config --cflags --libs gthread-2.0`
CFLAGS += `pkg-config --cflags`
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
CFLAGS += -Werror

include_HEADERS =  firewall.h conntrack.h rule_management.h helpers.h firewall_control.h hslist.h common_types.h
include_HEADERS += firewall_defines.h proxydb.h conndb.h esp_decrypt.h dlist.h
include_HEADERS += user_ipsec_api.h  user_ipsec_esp.h user_ipsec_sadb.h
include_HEADERS += proxy.h opptcp.h firewalldb.h lsi.h esp_prot_api.h esp_prot_fw_msg.h
include_HEADERS += esp_prot_conntrack.h user_ipsec_fw_msg.h esp_prot_config.h
include_HEADERS += sava_api.h cache.h cache_port.h esp_prot_defines.h datapkt.h
if HIP_MIDAUTH
include_HEADERS += midauth.h pisa.h pisa_cert.h
endif

INCLUDES = $(hipl_common_include_paths)

if HIP_FIREWALL

sbin_PROGRAMS = hipfw

hipfw_SOURCES = firewall.c conntrack.c rule_management.c helpers.c firewall_control.c esp_decrypt.c proxydb.c conndb.c dlist.c hslist.c
hipfw_SOURCES += user_ipsec_api.c user_ipsec_esp.c user_ipsec_sadb.c user_ipsec_fw_msg.c
hipfw_SOURCES += esp_prot_api.c esp_prot_fw_msg.c esp_prot_conntrack.c esp_prot_config.c
hipfw_SOURCES += proxy.c opptcp.c firewalldb.c lsi.c
hipfw_SOURCES += sava_api.c cache.c cache_port.c datapkt.c
if HIP_MIDAUTH
hipfw_SOURCES += midauth.c pisa.c pisa_cert.c
endif

hipfw_LDFLAGS =
hipfw_LDADD = -lipq

hipfw_LDADD += ../libhipcore/.libs/libhipcore.a
hipfw_LDADD += ../libinet6/.libs/libinet6.a

hipfw_LDADD += -lpthread
if HIP_UUIDLIB
    hipfw_LDADD += -luuid
endif

hipfw_LDADD += ../libhiptool/.libs/libhiptool.a

if HIP_PERFORMANCE
  hipfw_LDADD += ../performance/.libs/libperformance.a
endif

if HIP_I3
  INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
  hipfw_LDADD += ../i3/i3_client/libi3client.a ../i3/i3/libi3.a ../i3/utils/libutils.a ../i3/aeshash/libaes.a -lpthread
endif

endif

tags:
	etags $(hipfw_SOURCES) $(include_HEADERS)

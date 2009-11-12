AUTOMAKE_OPTIONS = foreign

#EXTRA_DIST = hip-fw-mi-svn-20060226.tar.gz

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.

CFLAGS = -g $(hipl_common_cflags) -I/usr/include/libipq/ -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPCORE_LIB)
# LDFLAGS = -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPCORE_LIB)
# -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
#CFLAGS += `pkg-config --cflags --libs glib-2.0` 
#CFLAGS += `pkg-config --cflags --libs gthread-2.0`
CFLAGS += `pkg-config --cflags`
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

include_HEADERS =  firewall.h conntrack.h rule_management.h helpers.h firewall_control.h 
include_HEADERS += hslist.h common_types.h firewall_defines.h dlist.h
include_HEADERS += user_ipsec_api.h  user_ipsec_esp.h user_ipsec_sadb.h
include_HEADERS += firewalldb.h lsi.h esp_prot_api.h esp_prot_fw_msg.h
include_HEADERS += esp_prot_conntrack.h user_ipsec_fw_msg.h 
include_HEADERS += cache.h cache_port.h esp_prot_defines.h
if HIP_MIDAUTH
include_HEADERS += midauth.h pisa.h pisa_cert.h
endif

INCLUDES = $(hipl_common_include_paths)

if HIP_FIREWALL
sbin_PROGRAMS = hipfw

hipfw_SOURCES = firewall.c conntrack.c rule_management.c helpers.c 
hipfw_SOURCES += firewall_control.c dlist.c hslist.c user_ipsec_api.c 
hipfw_SOURCES += user_ipsec_esp.c user_ipsec_sadb.c user_ipsec_fw_msg.c
hipfw_SOURCES += esp_prot_api.c esp_prot_fw_msg.c esp_prot_conntrack.c
hipfw_SOURCES += firewalldb.c lsi.c cache.c cache_port.c
endif

if HIP_MIDAUTH
hipfw_SOURCES += midauth.c pisa.c pisa_cert.c
endif

hipfw_LDFLAGS =
hipfw_LDADD = -lipq

if HIP_FORCE_SHLIB
    hipfw_LDADD += -linet6 -lhipcore -lhiptool
else
    hipfw_LDADD += ../libhipcore/.libs/libhipcore.a
endif

hipfw_LDADD += -lpthread
if HIP_UUIDLIB
    hipfw_LDADD += -luuid
endif

if HIP_FORCE_SHLIB
    hipfw_LDADD += -lhiptool
else
    hipfw_LDADD += ../libhiptool/.libs/libhiptool.a
endif

if HIP_PERFORMANCE
  hipfw_LDADD += ../performance/.libs/libperformance.a
endif

tags:
	etags $(hipfw_SOURCES) $(include_HEADERS)

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS = $(hipl_common_cflags)

sbin_PROGRAMS = hipd

hipd_SOURCES = update.c \
               hipd.c \
               keymat.c \
               blind.c \
               hiprelay.c \
               registration.c \
               user.c \
               hadb.c \
               oppdb.c \
               close.c \
               configfilereader.c \
               input.c \
               output.c \
               hidb.c \
               cookie.c \
               netdev.c \
               bos.c \
               nat.c \
               icookie.c \
               init.c \
               maintenance.c \
               accessor.c \
               oppipdb.c \
               dh.c \
               tcptimeout.c \
               cert.c \
               user_ipsec_sadb_api.c \
               user_ipsec_hipd_msg.c \
               esp_prot_hipd_msg.c \
               esp_prot_anchordb.c \
               hipqueue.c \
               esp_prot_light_update.c \
               nsupdate.c \
               hit_to_ip.c \
               update_legacy.c \
               hadb_legacy.c \
               heartbeat.c 

if HIP_MIDAUTH
hipd_SOURCES += pisa.c
endif

hipd_LDADD = ../libhipcore/.libs/libhipcore.a \
             ../libhipconf/.libs/libhipconf.a \
             ../libhiptool/.libs/libhiptool.a

if HIP_PERFORMANCE
hipd_LDADD += ../performance/.libs/libperformance.a
endif

if HIP_I3
hipd_SOURCES += hi3.c
hipd_LDADD += ../i3/i3_client/libi3client.a \
              ../i3/i3/libi3.a ../i3/utils/libutils.a \
              ../i3/aeshash/libaes.a
endif

if HIP_OPENDHT
hipd_SOURCES += dht.c
hipd_LDADD += ../libdht/.libs/libhipopendht.a
endif

if HIP_PFKEY
hipd_SOURCES += pfkeyapi.c
hipd_LDADD += ../libipsec/.libs/libhipsec.a
endif

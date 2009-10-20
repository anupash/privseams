
AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
CFLAGS += -DHIPL_DEFAULT_PREFIX=\"$(prefix)\"

include_HEADERS =  hadb.h oppdb.h hipd.h netdev.h user.h hiprelay.h
include_HEADERS += input.h output.h 
include_HEADERS += close.h keymat.h configfilereader.h
include_HEADERS += cookie.h hidb.h nat.h update.h dh.h registration.h
include_HEADERS += init.h maintenance.h accessor.h
include_HEADERS += cert.h user_ipsec_sadb_api.h user_ipsec_hipd_msg.h
include_HEADERS += esp_prot_hipd_msg.h esp_prot_anchordb.h esp_prot_light_update.h
include_HEADERS += nsupdate.h hit_to_ip.h

INCLUDES = $(hipl_common_include_paths)

sbin_PROGRAMS = hipd
hipd_SOURCES = update.c hipd.c keymat.c hiprelay.c registration.c
hipd_SOURCES += user.c hadb.c oppdb.c close.c configfilereader.c
hipd_SOURCES += input.c output.c hidb.c cookie.c netdev.c nat.c
hipd_SOURCES += init.c maintenance.c accessor.c dh.c
hipd_SOURCES += cert.c user_ipsec_sadb_api.c user_ipsec_hipd_msg.c
hipd_SOURCES += esp_prot_hipd_msg.c esp_prot_anchordb.c esp_prot_light_update.c
hipd_SOURCES += nsupdate.c hit_to_ip.c

hipd_LDFLAGS = -lcrypto $(HIPL_XMLL) -lm -DHIPL_HIPD

if HIP_FORCE_SHLIB
hipd_LDADD = $(OPENWRT_LIB_STATIC) -linet6 ../libhipcore/.libs/libhipcore.a
else
hipd_LDADD = $(OPENWRT_LIB_STATIC) ../libhipcore/.libs/libhipcore.a
endif

if HIP_FORCE_SHLIB
  hipd_LDFLAGS += -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
  hipd_LDADD += -lhiptool -lhipcore
else
  hipd_LDADD += ../libhipcore/.libs/libhipcore.a
  hipd_LDADD += ../libhiptool/.libs/libhiptool.a
endif

if HIP_UUIDLIB
hipd_LDADD += -luuid
endif

if HIP_PRIVSEP
if HIP_ALTSEP
  hipd_LDFLAGS += ../libhipcore/.libs/libhipcore.a
else
  hipd_LDFLAGS += -lcap ../libhipcore/.libs/libhipcore.a
endif
endif

if HIP_PFKEY
hipd_LDADD += ../libipsec/.libs/libipsec.a
hipd_SOURCES += pfkeyapi.c
endif

# KeyNotev2
#INCLUDES += -Ikeynote
#hipd_LDADD += keynote/.libs/libkeynote.a
#SUBDIRS += keynote

../libdht/.libs/libdhttracker.a:
	$(MAKE) -C $(HIPL)/libdht

../libdht/.libs/libdhtresolver.a:
	$(MAKE) -C $(HIPL)/libdht



# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#

cookie.c: cookie.h
hidb.c: hidb.h
hadb.c: hadb.h
oppdb.c:oppdb.h
keymat.c: keymat.h
user.c: user.h
input.c: input.h
output.c: output.h
nat.c : nat.h
netdev.c: netdev.h
update.c: update.h
registration.c: registration.h
hiprelay.c: hiprelay.h
configfilereader.c: configfilereader.h
registration.c: registration.h
linkedlist.c: linkedlist.h

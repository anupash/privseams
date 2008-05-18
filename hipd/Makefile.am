AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)

# Note: libinet6 cannot be included here because it has a bad dependency
# with netlink headers.
include_HEADERS =  hadb.h oppdb.h hipd.h netdev.h user.h hiprelay.h
include_HEADERS += bos.h input.h output.h icookie.h blind.h linkedlist.h
include_HEADERS += close.h hi3.h keymat.h timer.h configfilereader.h
include_HEADERS += cookie.h hidb.h nat.h update.h dh.h registration.h
include_HEADERS += escrow.h reg.h init.h maintenance.h accessor.h oppipdb.h
include_HEADERS += tcptimeout.h  

INCLUDES = $(hipl_common_include_paths)

sbin_PROGRAMS = hipd
hipd_SOURCES = reg.c update.c hipd.c keymat.c blind.c hiprelay.c registration.c
hipd_SOURCES += user.c hadb.c oppdb.c close.c configfilereader.c linkedlist.c
hipd_SOURCES += input.c output.c hidb.c cookie.c netdev.c bos.c nat.c icookie.c
hipd_SOURCES += escrow.c init.c maintenance.c accessor.c oppipdb.c dh.c
hipd_SOURCES += tcptimeout.c

# Put these library directories in the library search path:

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
hipd_LDADD = ../libinet6/.libs/libinet6.a

if HIP_CORPORATE
  hipd_LDADD += -lhiptool
else
  hipd_LDADD += ../libhiptool/.libs/libhiptool.a
endif

# Required for pjsip
hipd_LDADD += -lpthread
hipd_LDADD += ../pjproject/pjnath/lib/libpjnath-${host}.a
hipd_LDADD += ../pjproject/pjsip/lib/libpjsip-${host}.a
hipd_LDADD += ../pjproject/pjsip/lib/libpjsip-ua-${host}.a
hipd_LDADD += ../pjproject/pjsip/lib/libpjsip-simple-${host}.a
hipd_LDADD += ../pjproject/pjsip/lib/libpjsua-${host}.a
hipd_LDADD += ../pjproject/pjmedia/lib/libpjmedia-${host}.a
hipd_LDADD += ../pjproject/pjmedia/lib/libpjmedia-codec-${host}.a
hipd_LDADD += ../pjproject/pjlib/lib/libpj-${host}.a
hipd_LDADD += ../pjproject/pjlib-util/lib/libpjlib-util-${host}.a

../pjproject/pjlib/lib/libpj-${host}.a:
../pjproject/pjlib-util/lib/libpjlib-util-${host}.a:
../pjproject/pjnath/lib/libpjnath-${host}.a:
../pjproject/pjsip/lib/libpjsip-${host}.a:
../pjproject/pjsip/lib/libpjsip-ua-${host}.a:
../pjproject/pjsip/lib/libpjsip-simple-${host}.a:
../pjproject/pjsip/lib/libpjsua-${host}.a:
../pjproject/pjmedia/lib/libpjmedia-${host}.a:
../pjproject/pjmedia/lib/libpjmedia-codec-${host}.a:

hipd_LDFLAGS = -lcrypto $(HIPL_XMLL) -lm -DHIPL_HIPD

if HIP_HI3
 hipd_SOURCES += hi3.c
 INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
 hipd_LDADD += ../i3/i3_client/libi3client.a ../i3/i3/libi3.a ../i3/utils/libutils.a ../i3/aeshash/libaes.a -lpthread
endif

hipd_LDADD += ../opendht/.libs/libhipopendht.a

if HIP_PFKEY
hipd_LDADD += ../libipsec/.libs/libipsec.a
hipd_SOURCES += pfkeyapi.c
endif

# KeyNotev2
#INCLUDES += -Ikeynote
#hipd_LDADD += keynote/.libs/libkeynote.a
#SUBDIRS += keynote

../opendht/.libs/libdhttracker.a:
	$(MAKE) -C $(HIPL)/opendht

../opendht/.libs/libdhtresolver.a:
	$(MAKE) -C $(HIPL)/opendht



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
bos.c: bos.h
input.c: input.h
output.c: output.h
nat.c : nat.h
netdev.c: netdev.h
update.c: update.h
icookie.c: icookie.h
escrow.c: escrow.h
reg.c: reg.h
blind.c: blind.h
tcptimeout.c: tcptimeout.h
hiprelay.c: hiprelay.h
configfilereader.c: configfilereader.h
registration.c: registration.h
linkedlist.c: linkedlist.h


AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)

# Note: libinet6 cannot be included here because it has a bad dependency
# with netlink headers.
include_HEADERS = cookie.h hidb.h hadb.h hashtable.h keymat.h keymat.h \
                  workqueue.h bos.h input.h output.h preoutput.h preinput.h \
                  xfrm.h beet.h netdev.h update.h rvs.h
INCLUDES = $(hipl_common_include_paths)

sbin_PROGRAMS = hipd
hipd_SOURCES = rvs.c preinput.c update.c beet.c hipd.c hashtable.c keymat.c
hipd_SOURCES += workqueue.c preoutput.c hadb.c
hipd_SOURCES += input.c output.c hidb.c cookie.c netdev.c bos.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
hipd_LDADD = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a
hipd_LDFLAGS = -lcrypto

#SUBDIRS =

# Hi3
#CFLAGS += -DCONFIG_HIP_HI3
#hipd_SOURCES += hi3.c
#INCLUDES += -Ii3/i3_client -Ii3/utils -Ii3/i3
#hipd_LDADD += i3/i3_client/.libs/libi3client.a i3/aeshash/.libs/libaes.a
#SUBDIRS += i3

# KeyNotev2
#INCLUDES += -Ikeynote
#hipd_LDADD += keynote/.libs/libkeynote.a
#SUBDIRS += keynote

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#

cookie.c: cookie.h
hidb.c: hidb.h
hadb.c: hadb.h
hashtable.c: hashtable.h
keymat.c: keymat.h
workqueue.c: workqueue.h
bos.c: bos.h
input.c: input.h
output.c: output.h
preoutput.c: preoutput.h
preinput.c: preinput.h
xfrm.c: xfrm.h
beet.c: beet.h
netdev.c: netdev.h
update.c: update.h
rvs.c: rvs.h


AUTOMAKE_OPTIONS = foreign

# Specify HIPL topdir manually. top_srcdir may not work otherwise if configure
# is invoked manually directly in this dir. The global include file uses the
# HIPL variable to setup some HIPL_* variables.
# 
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = -DHIP_LOGFMT_LONG -g -DCONFIG_HIP_DEBUG -DCONFIG_HIP_DAEMON

include_HEADERS = hipd.h crypto.h netlink.h
INCLUDES += -I$(HIPL_LINUX_INCLUDE) -I$(PWD) -I$(HIPL_LIBHIPTOOL)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL_LINUX_MODULE) -I$(HIPL)

sbin_PROGRAMS = hipd
hipd_SOURCES = pk.c rvs.c preinput.c update.c netdev.c beet.c hipd.c hashtable.c keymat.c 
hipd_SOURCES += workqueue.c builder.c preoutput.c hadb.c crypto.c
hipd_SOURCES += input.c output.c xfrm.c hidb.c cookie.c misc.c dh.c netlink.c bos.c debug.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
hipd_LDADD = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a
hipd_LDFLAGS = -lcrypto

SUBDIRS =

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

builder.c: builder.h
cookie.c: cookie.h
crypto.c: crypto.h
hidb.c: hidb.h
dh.c: dh.h
hadb.c: hadb.h
hashtable.c: hashtable.h
keymat.c: keymat.h
misc.c: misc.h
workqueue.c: workqueue.h
bos.c: bos.h
input.c: input.h
output.c: output.h
preoutput.c: preoutput.h
preinput.c: preinput.h
xfrm.c: xfrm.h
beet.c: beet.h
update.c: update.h
rvs.c: rvs.h
pk.c: pk.h
debug.c: debug.h


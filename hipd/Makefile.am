AUTOMAKE_OPTIONS = foreign

# Specify HIPL topdir manually. top_srcdir may not work otherwise if configure
# is invoked manually directly in this dir. The global include file uses the
# HIPL variable to setup some HIPL_* variables.
# 
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = -DHIP_LOGFMT_LONG -g -DCONFIG_HIP_DEBUG -DCONFIG_HIP_USERSPACE 
CFLAGS = -DCONFIG_HIP_AGENT

include_HEADERS = hipd.h crypto.h netlink.h
INCLUDES = -I$(HIPL_LINUX_INCLUDE) -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL_LINUX_MODULE) -I$(HIPL)

sbin_PROGRAMS = hipd
hipd_SOURCES = pk.c rvs.c preinput.c update.c netdev.c beet.c hipd.c hashtable.c keymat.c 
hipd_SOURCES += workqueue.c builder.c preoutput.c hadb.c crypto.c
hipd_SOURCES += input.c output.c xfrm.c hidb.c cookie.c misc.c dh.c netlink.c bos.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
hipd_LDADD = ../libinet6/.libs/libinet6.a
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
builder.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.h .
builder.c: builder.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.c .
cookie.c: cookie.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/cookie.c .
cookie.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/cookie.h .
crypto.c: crypto.h
crypto.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/crypto.h .
hidb.c: hidb.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hidb.c .
hidb.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hidb.h .
dh.c: dh.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/dh.c .
dh.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/dh.h .
hadb.c: hadb.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hadb.c .
hadb.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hadb.h .
netlink.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/netlink.h .
hashtable.c: hashtable.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hashtable.c .
hashtable.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hashtable.h .
keymat.c: keymat.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/keymat.c .
keymat.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/keymat.h .
misc.c: misc.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/misc.c .
misc.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/misc.h .
workqueue.c: workqueue.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/workqueue.c .
workqueue.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/workqueue.h .
bos.c: 
	$(LN_S) -f $(HIPL_LINUX_MODULE)/bos.c .
bos.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/bos.h .
input.c: input.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/input.c .
output.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/output.h .
output.c: output.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/output.c .
input.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/input.h .
timer.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/timer.h .
preoutput.c: preoutput.h
preoutput.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preoutput.h .
preinput.c: preinput.h
preinput.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preinput.h .
xfrm.c: xfrm.h
xfrm.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/xfrm.h .
beet.c: beet.h
beet.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/beet.h .
update.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/update.h .
update.c: update.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/update.c .
rvs.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/rvs.h .
rvs.c: rvs.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/rvs.c .
pk.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/pk.h .
pk.c: pk.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/pk.c .

tags:
	etags $(hipd_SOURCES) $(include_HEADERS)


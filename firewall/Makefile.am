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
CFLAGS += -I$(HIPL_TOOLS) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL)
CFLAGS += -I$(HIPL_HIPD)
CFLAGS += -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g
CFLAGS += -L$(HIPL_LIBINET6_LIB)
CFLAGS += `pkg-config --cflags --libs glib-2.0` 
CFLAGS += `pkg-config --cflags --libs gthread-2.0`

include_HEADERS =  netlink.h 
include_HEADERS += firewall.h conntrack.h rule_management.h helpers.h builder.h misc.h pk.h 
INCLUDES = -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_LIBHIPTOOL)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL) -I$(HIPL_HIPD)

sbin_PROGRAMS = firewall

firewall_SOURCES = firewall.c conntrack.c rule_management.c helpers.c
firewall_SOURCES +=  builder.c misc.c dh.c pk.c

firewall_LDADD = /usr/lib/libipq.a ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a

SUBDIRS =

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
cookie.c: cookie.h
	$(LN_S) -f $(HIPL_HIPD)/cookie.c .
cookie.h:
	$(LN_S) -f $(HIPL_HIPD)/cookie.h .
hidb.c: hidb.h
	$(LN_S) -f $(HIPL_HIPD)/hidb.c .
hidb.h:
	$(LN_S) -f $(HIPL_HIPD)/hidb.h .
dh.h:
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/dh.h .
dh.c: dh.h
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/dh.c .
hadb.c: hadb.h
	$(LN_S) -f $(HIPL_HIPD)/hadb.c .
hadb.h:
	$(LN_S) -f $(HIPL_HIPD)/hadb.h .
netlink.h:
	$(LN_S) -f $(HIPL_HIPD)/netlink.h .
hashtable.c: hashtable.h 
	$(LN_S) -f $(HIPL_HIPD)/hashtable.h .	
hashtable.h:
	$(LN_S) -f $(HIPL_HIPD)/hashtable.h .
keymat.c: keymat.h
	$(LN_S) -f $(HIPL_HIPD)/keymat.c .
keymat.h:
	$(LN_S) -f $(HIPL_HIPD)/keymat.h .
misc.h:
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/misc.h .
misc.c: misc.h
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/misc.c .
builder.h:
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/builder.h .
builder.c: builder.h
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/builder.c .
workqueue.c: workqueue.h
	$(LN_S) -f $(HIPL_HIPD)/workqueue.c .
workqueue.h:
	$(LN_S) -f $(HIPL_HIPD)/workqueue.h .
input.c: input.h
	$(LN_S) -f $(HIPL_HIPD)/input.c .
output.h:
	$(LN_S) -f $(HIPL_HIPD)/output.h .
output.c: output.h
	$(LN_S) -f $(HIPL_HIPD)/output.c .
input.h:
	$(LN_S) -f $(HIPL_HIPD)/input.h .
timer.h:
	$(LN_S) -f $(HIPL_HIPD)/timer.h .
preoutput.c: preoutput.h
	$(LN_S) -f $(HIPL_HIPD)/preoutput.c .
preoutput.h:
	$(LN_S) -f $(HIPL_HIPD)/preoutput.h .
preinput.c: preinput.h
	$(LN_S) -f $(HIPL_HIPD)/preinput.c .
preinput.h:
	$(LN_S) -f $(HIPL_HIPD)/preinput.h .
xfrm.c: xfrm.h
	$(LN_S) -f $(HIPL_HIPD)/xfrm.c .
xfrm.h:
	$(LN_S) -f $(HIPL_HIPD)/xfrm.h .
beet.c: beet.h
	$(LN_S) -f $(HIPL_HIPD)/beet.c .
beet.h:
	$(LN_S) -f $(HIPL_HIPD)/beet.h .
update.h:
	$(LN_S) -f $(HIPL_HIPD)/update.h
update.c: update.h
	$(LN_S) -f $(HIPL_HIPD)/update.c
rvs.h:
	$(LN_S) -f $(HIPL_HIPD)/rvs.h
rvs.c: rvs.h
	$(LN_S) -f $(HIPL_HIPD)/rvs.c
pk.h:
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/pk.h
pk.c: pk.h
	$(LN_S) -f $(HIPL_LIBHIPTOOL)/pk.c
tags:
	etags $(firewall_SOURCES) $(include_HEADERS)


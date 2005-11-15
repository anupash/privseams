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
CFLAGS += -I$(HIPL_LINUX_INCLUDE) -I$(HIPL_LINUX_MODULE) -I$(HIPL_HIPD)
CFLAGS += -I/usr/include/libipq/ -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g
CFLAGS += -L$(HIPL_LIBINET6_LIB)
CFLAGS += `pkg-config --cflags --libs glib-2.0` 
CFLAGS += `pkg-config --cflags --libs gthread-2.0`

include_HEADERS =  crypto.h netlink.h 
include_HEADERS += firewall.h conntrack.h rule_management.h helpers.h builder.h misc.h pk.h  
INCLUDES = -I$(HIPL_LINUX_INCLUDE) -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL_LINUX_MODULE) -I$(HIPL)	-I$(HIPL_HIPD)

sbin_PROGRAMS = firewall

firewall_SOURCES = firewall.c conntrack.c rule_management.c helpers.c
firewall_SOURCES +=  builder.c misc.c crypto.c dh.c pk.c

firewall_LDADD = /usr/lib/libipq.a ../libinet6/.libs/libinet6.a  

SUBDIRS =

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
	$(LN_S) -f $(HIPL_HIPD)/crypto.c .
#crypto.h
crypto.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/crypto.h .
hidb.c: hidb.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hidb.c .
hidb.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hidb.h .
#debug.c: debug.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/debug.c .
#debug.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/debug.h .
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
	$(LN_S) -f $(HIPL_HIPD)/hashtable.h .	
#hashtable.h
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
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preoutput.c .
preoutput.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preoutput.h .
preinput.c: preinput.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preinput.c .
preinput.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preinput.h .
xfrm.c: xfrm.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/xfrm.c .
xfrm.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/xfrm.h .
beet.c: beet.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/beet.c .
beet.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/beet.h .
update.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/update.h
update.c: update.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/update.c
rvs.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/rvs.h
rvs.c: rvs.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/rvs.c
pk.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/pk.h
pk.c: pk.h
	$(LN_S) -f $(HIPL_HIPD)/pk.c
tags:
	etags $(firewall_SOURCES) $(include_HEADERS)


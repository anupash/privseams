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

include_HEADERS = hipd.h
INCLUDES = -I$(HIPL_LINUX_INCLUDE) -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL_LINUX_MODULE)

sbin_PROGRAMS = hipd
hipd_SOURCES = hipd.c netlink.c workqueue.c builder.c hadb.c
hipd_SOURCES += input.c preoutput.c

# i3 and KeyNotev2 specific includes/libraries:
#-Ii3/i3_client -Ii3/utils -Ii3/i3 -Ikeynote
#hipd_LDADD = keynote/.libs/libkeynote.a
#hipd_LDADD += i3/i3_client/.libs/libi3client.a i3/aeshash/.libs/libaes.a

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
hipd_LDADD    = ../libinet6/.libs/libinet6.a
hipd_LDFLAGS  = -lcrypto

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
builder.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.h .
builder.c: builder.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.c .
#cookie.c: cookie.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/cookie.c .
#cookie.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/cookie.h .
#db.c: db.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/db.c .
#db.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/db.h .
hadb.c: hadb.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hadb.c .
hadb.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/hadb.h .
netlink.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/netlink.h .
#hashtable.c: hashtable.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/hashtable.c .
#hashtable.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/hashtable.h .
#hip.c: hip.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/hip.c .
#hip.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/hip.h .
#keymat.c: keymat.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/keymat.c .
#keymat.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/keymat.h .
input.c: input.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/input.c .
input.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/input.h .
preoutput.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/preoutput.h .

#SUBDIRS = keynote i3




AUTOMAKE_OPTIONS = foreign

# Specify HIPL topdir manually. top_srcdir may not work otherwise if configure
# is invoked manually directly in this dir. The global include file uses the
# HIPL variable to setup some HIPL_* variables.
# 
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS  += -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_LINUX_INCLUDE)
CFLAGS  += -I$(HIPL_LINUX_MODULE) -I$(HIPL) -DCONFIG_HIP_DEBUG
CFLAGS  += -DHIP_LOGFMT_LONG -g -L$(HIPL_LIBINET6_LIB)

include_HEADERS = hipconf.h

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
LDADD    = ../libinet6/.libs/libinet6.a

LDFLAGS += -lcrypto

bin_PROGRAMS = hipconf
hipconf_SOURCES = hipconf.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
builder.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.h .
builder.c: builder.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.c .
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

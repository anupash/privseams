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
CFLAGS += -I$(HIPL_HIPD) -I/usr/include/libipq/
CFLAGS += -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g
CFLAGS += -L$(HIPL_LIBINET6_LIB)
CFLAGS += `pkg-config --cflags --libs glib-2.0` 
CFLAGS += `pkg-config --cflags --libs gthread-2.0`

include_HEADERS = firewall.h conntrack.h rule_management.h helpers.h
INCLUDES = -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_LIBHIPTOOL)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL) -I$(HIPL_HIPD)

sbin_PROGRAMS = firewall

firewall_SOURCES = firewall.c conntrack.c rule_management.c helpers.c

firewall_LDADD = /usr/lib/libipq.a ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a

tags:
	etags $(firewall_SOURCES) $(include_HEADERS)

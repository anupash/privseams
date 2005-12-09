AUTOMAKE_OPTIONS = foreign

# Specify HIPL topdir manually. top_srcdir may not work otherwise if configure
# is invoked manually directly in this dir. The global include file uses the
# HIPL variable to setup some HIPL_* variables.
# 
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

WX_CFLAGS := $(shell wx-config --libs)

GTK_CFLAGS := $(shell gtk-config --cflags --libs)

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = -DHIP_LOGFMT_LONG -g -DCONFIG_HIP_DEBUG -DCONFIG_HIP_USERSPACE
CFLAGS += -DCONFIG_HIP_AGENT $(WX_LDFLAGS) $(GTK_CFLAGS)

include_HEADERS = crypto.h netlink.h
INCLUDES = -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_LIBHIPGUI)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL) -I$(HIPL_LIBHIPTOOL) # -I$(HIPL_HIPD)

sbin_PROGRAMS = agent
agent_SOURCES = agent.c agent_tools.c connhipd.c hit_db.c gui_interface.c
#agent_cmd_SOURCES = agent.c agent_tools.c connhipd.c hit_db.c gui_interface.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
agent_LDADD = ../libinet6/.libs/libinet6.a ../libhipgui/.libs/libhipgui.a
agent_LDADD += ../libhiptool/.libs/libhiptool.a
agent_LDFLAGS = -lcrypto -lpthread $(WX_CFLAGS)
#agent_CFLAGS = $(CFLAGS)

#agent_cmd_LDADD = ../libinet6/.libs/libinet6.a ./gui/.libs/libhipgui.a
#agent_cmd_LDFLAGS = -lcrypto -lpthread
#agent_cmd_CFLAGS = $(CFLAGS) 

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
#builder.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.h .
#builder.c: builder.h
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.c .
#crypto.c: crypto.h
#crypto.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/crypto.h .
#netlink.h:
#	$(LN_S) -f $(HIPL_LINUX_MODULE)/netlink.h .

tags:
	etags $(hipd_SOURCES) $(include_HEADERS)


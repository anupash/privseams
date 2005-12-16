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
CFLAGS = $(WX_LDFLAGS) $(GTK_CFLAGS) $(GDB_CFLAG)

include_HEADERS = 
INCLUDES = -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_LIBHIPGUI)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL) -I$(HIPL_LIBHIPTOOL)

sbin_PROGRAMS = agent
agent_SOURCES = agent.c agent_tools.c connhipd.c hit_db.c gui_interface.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
agent_LDADD = ../libinet6/.libs/libinet6.a ../libhipgui/.libs/libhipgui.a
agent_LDADD += ../libhiptool/.libs/libhiptool.a
agent_LDFLAGS = -lcrypto -lpthread $(WX_CFLAGS)

tags:
	etags $(hipd_SOURCES) $(include_HEADERS)


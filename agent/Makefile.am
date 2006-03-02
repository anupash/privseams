AUTOMAKE_OPTIONS = foreign

WX_CFLAGS := $(shell wx-config --libs)

GTK_CFLAGS := $(shell gtk-config --cflags --libs)

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags) $(WX_LDFLAGS) $(GTK_CFLAGS)

include_HEADERS = 
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPGUI)

sbin_PROGRAMS = agent
agent_SOURCES = agent_gtk.c agent_tools.c connhipd.c hit_db.c gui_interface.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
agent_LDADD = ../libinet6/.libs/libinet6.a ../libhipgui/.libs/libhipgui.a
agent_LDADD += ../libhiptool/.libs/libhiptool.a
agent_LDFLAGS = -lcrypto -lpthread $(WX_CFLAGS)

tags:
	etags $(hipd_SOURCES) $(include_HEADERS)


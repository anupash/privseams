AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)

GTKLDADD   = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

include_HEADERS = agent_tools.h gui_interface.h connhipd.h agent.h hit_db.h
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPGUI) -I$(HIPL_LIBINET6_INCLUDE)

if HIP_AGENT

bin_PROGRAMS = hipagent
hipagent_SOURCES = agent_gtk.c agent_tools.c connhipd.c hit_db.c gui_interface.c str_var.c language.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
# Somewhy @GTK_LIBS@ must be includec here, not enough that its in libhipgui
# Makefile.am... Fix someday?
#hipagent_LDADD += ../libhiptool/.libs/libhiptool.a @GTK_LIBS@
hipagent_LDADD = ../libhipgui/libhipgui.a ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a
if HIP_OPENDHT
  hipagent_LDADD += ../opendht/.libs/libhipopendht.a
endif

hipagent_LDFLAGS = -lcrypto -lpthread $(GTKLDADD) $(GTHREADLDADD) $(GOBJECTLDADD)

endif

tags:
	etags $(hipagent_SOURCES) $(include_HEADERS)


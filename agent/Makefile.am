AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags) @GTK_CFLAGS@

if HIP_AGENT

GTKLDADD = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD = `pkg-config --cflags --libs gobject-2.0`

sbin_PROGRAMS = hipagent

hipagent_SOURCES = agent.c \
                   tools.c \
                   connhipd.c \
                   hitdb.c \
                   gui_interface.c \
                   str_var.c \
                   language.c

# hard dependencies: libhipgui, libhipcore
# TODO ../libhipgui/libhipgui.a should be in .libs
# TODO fix dependency between libhipgui and libhipconf if possible
# TODO fix dependency between libhipcore and libhipconf if possible
# TODO fix dependency between libhipconf and libhipopendht if possible
# TODO fix dependency between (libhipconf, libhipcore) and libhiptool if possible
hipagent_LDADD = ../libhipgui/libhipgui.a \
                 ../libhipconf/.libs/libhipconf.a \
                 ../libhipcore/.libs/libhipcore.a \
                 ../libhiptool/.libs/libhiptool.a \
                 ../libdht/.libs/libhipopendht.a

hipagent_LDFLAGS = $(GTKLDADD) \
                   $(GTHREADLDADD) \
                   $(GOBJECTLDADD)

endif

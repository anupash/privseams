AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

GTKLDADD = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD = `pkg-config --cflags --libs gobject-2.0`

sbin_PROGRAMS = hipagent

# NOTE: gtk does not allow for -Wstrict-prototypes, so we need to append AM_CFLAGS
hipagent_CFLAGS = @GTK_CFLAGS@ -Werror -Wall -Wcast-align -Wdisabled-optimization -Wundef -fno-strict-aliasing

hipagent_SOURCES = agent.c \
                   tools.c \
                   connhipd.c \
                   hitdb.c \
                   gui_interface.c \
                   str_var.c \
                   language.c

# hard dependencies: libhipgui, libhipcore
# TODO fix dependency between libhipgui and libhipconf if possible
# TODO fix dependency between libhipcore and libhipconf if possible
# TODO fix dependency between libhipconf and libhipopendht if possible
# TODO fix dependency between (libhipconf, libhipcore) and libhiptool if possible
hipagent_LDADD = ../libhipgui/libhipgui.la \
                 ../libhipconf/libhipconf.la \
                 ../libhipcore/libhipcore.la \
                 ../libhiptool/libhiptool.la \
                 ../libdht/libhipopendht.la
                 
if HIP_PERFORMANCE
hipagent_LDADD += ../performance/libperformance.la
endif

hipagent_LDFLAGS = $(GTKLDADD) \
                   $(GTHREADLDADD) \
                   $(GOBJECTLDADD)

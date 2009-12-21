AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)

GTKLDADD   = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPGUI) -I$(HIPL_LIBINET6_INCLUDE)  -I$(HIPL_LIBHIPCORE_INCLUDE) -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include @GTK_CFLAGS@

if HIP_AGENT

CFLAGS += -lsqlite3

sbin_PROGRAMS = hipagent

hipagent_SOURCES = agent.c \
                   tools.c \
                   connhipd.c \
                   hitdb.c \
                   gui_interface.c \
                   str_var.c \
                   language.c

hipagent_LDADD = ../libhipgui/libhipgui.a

if HIP_LIBINET6
hipagent_LDADD += ../libinet6/.libs/libinet6.a
endif

hipagent_LDADD += ../libhipcore/.libs/libhipcore.a \
                 ../libhiptool/.libs/libhiptool.a \
                 ../libhipconf/.libs/libhipconf.a \
                 ../libdht/.libs/libhipopendht.a

if HIP_PERFORMANCE
hipagent_LDADD += ../performance/.libs/libperformance.a
endif

hipagent_LDFLAGS = $(GTKLDADD) $(GTHREADLDADD) $(GOBJECTLDADD)

endif

# This is needed when getting a fresh checkout and "./autogen.sh && ./configure && make install"
# (i.e. the intermediate "make (all)" is missing. Fixes also rpm compilation. -miika
../libhipgui/libhipgui.a:
	make -C ../libhipgui

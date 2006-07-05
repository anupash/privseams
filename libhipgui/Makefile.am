## Makefile.am for HIP GUI

AM_CFLAGS = $(hipl_common_cflags) -O0

GTKCFLAGS  = `pkg-config gtk+-2.0 --cflags`
GTKLDADD   = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

include_HEADERS =
INCLUDES = $(hipl_common_include_paths)

if HIP_AGENT

sbin_PROGRAMS = hipstart
noinst_LIBRARIES = libhipgui.a

hipstart_SOURCES = hipstart.c widgets.c
libhipgui_a_SOURCES = main.c events.c manage.c widgets.c exec.c tools.c terminal.c tw_create.c tw_manage.c main_create.c nh_create.c create.c nh_manage.c


hipstart_LDFLAGS = $(CFLAGS) $(GTKCFLAGS) $(GTHREADLDADD) $(GOBJECTLDADD)
hipstart_LDADD = ../libhiptool/.libs/libhiptool.a

#libhipgui_a_CFLAGS = $(CFLAGS) @GTK_CFLAGS@
libhipgui_a_CFLAGS = $(CFLAGS) $(GTKCFLAGS) $(GTHREADLDADD) $(GOBJECTLDADD)

INCLUDES += -I$(HIPL_AGENT) $(GTKCFLAGS)

endif

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)


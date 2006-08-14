## Makefile.am for HIP GUI
AUTOMAKE_OPTIONS = foreign

GTKCFLAGS  = `pkg-config gtk+-2.0 --cflags`
GTKLDADD   = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

CFLAGS = $(hipl_common_cflags)

include_HEADERS =
INCLUDES =

if HIP_AGENT

libhipgui_adir = $(pkgdatadir)/libhipgui

sbin_PROGRAMS = hipstart
noinst_LIBRARIES = libhipgui.a

hipstart_SOURCES = hipstart.c widgets.c
libhipgui_a_SOURCES = main.c events.c manage.c widgets.c exec.c tools.c terminal.c tw_create.c tw_manage.c main_create.c nh_create.c create.c nh_manage.c terminal_server.c terminal_client.c
libhipgui_a_DATA = logo.png run.png swtool.png newgroup.png

hipstart_LDFLAGS = $(CFLAGS) $(GTKCFLAGS) $(GTHREADLDADD) $(GOBJECTLDADD)
hipstart_LDADD = ../libhiptool/.libs/libhiptool.a

#libhipgui_a_CFLAGS = $(CFLAGS) @GTK_CFLAGS@
libhipgui_a_CFLAGS = $(CFLAGS) $(GTKCFLAGS) $(GTHREADLDADD) $(GOBJECTLDADD) ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a -DHIP_GUI_DATADIR=\"$(pkgdatadir)/libhipgui\"

INCLUDES += $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_AGENT) $(GTKCFLAGS)

endif

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)


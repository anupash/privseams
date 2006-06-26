## Makefile.am for HIP GUI

AM_CFLAGS = $(hipl_common_cflags) -O0

GTKCFLAGS  = `pkg-config gtk+-2.0 --cflags`
GTKLDADD   = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

include_HEADERS = 

#if HIP_AGENT

noinst_LIBRARIES = libhipgui.a
libhipgui_a_SOURCES = \
	main.c \
	events.c \
	manage.c \
	widgets.c \
	exec.c \
	tools.c \
	terminal.c \
	tw_manage.c \
	main_create.c


#libhipgui_a_CFLAGS = $(CFLAGS) @GTK_CFLAGS@
libhipgui_a_CFLAGS = $(CFLAGS) $(GTKCFLAGS) $(GTHREADLDADD) $(GOBJECTLDADD)

INCLUDES = $(hipl_common_include_paths)
#INCLUDES += -I$(HIPL_AGENT) @GTK_CFLAGS@
INCLUDES += -I$(HIPL_AGENT) $(GTKCFLAGS)

#endif

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)


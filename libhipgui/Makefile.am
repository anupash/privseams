## Makefile.am for HIP GUI
CFLAGS = $(hipl_common_cflags) -O0

# XX TODO: when wxgtk 2.6.2 ends in normal distros, configure without wx-config
GTK_INCLUDES := $(shell pkg-config --cflags gtk+-2.0)
GTK_CFLAGS := $(shell pkg-config --libs gtk+-2.0)

lib_LTLIBRARIES = libhipgui.la

libhipgui_la_SOURCES = gui_event.c gui_main.c gui_manage.c

libhipgui_la_CFLAGS = $(GTK_CFLAGS) $(CFLAGS)
#libhipgui_la_LIBADD =

INCLUDES = $(hipl_common_include_paths)
INCLUDES += $(GTK_INCLUDES) -I$(HIPL_AGENT)

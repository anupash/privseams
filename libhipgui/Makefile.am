## Makefile.am for HIP GUI
AM_CFLAGS = $(hipl_common_cflags) -O0

include_HEADERS = 

noinst_LIBRARIES = libhipgui.a

libhipgui_a_SOURCES = gui_event.c gui_main.c gui_manage.c

libhipgui_a_CFLAGS = $(CFLAGS) @GTK_CFLAGS@

INCLUDES = $(hipl_common_include_paths)
INCLUDES += -I$(HIPL_AGENT) @GTK_CFLAGS@

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)


## Makefile.am for HIP GUI
AUTOMAKE_OPTIONS = foreign

#GTKCFLAGS  = `pkg-config gtk+-2.0 --cflags`
#GTKLDADD   = `pkg-config gtk+-2.0 --libs`
#GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
#GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

include_HEADERS = create.h  events.h  exec.h  hipstart.h  main.h  manage.h  nh.h  rhit_dnd.h  terminal.h  tools.h  tw.h  widgets.h  x.h

CFLAGS = $(hipl_common_cflags)

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)


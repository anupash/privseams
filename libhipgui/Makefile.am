## Makefile.am for HIP GTK GUI
AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags)
CFLAGS += -D__USE_GNU

if HIP_AGENT
libhipgui_adir = $(pkgdatadir)/libhipgui

noinst_LIBRARIES = libhipgui.a

include_HEADERS = create.h  dragndrop.h  events.h  hipgui.h  tools.h  widgets.h

libhipgui_a_SOURCES = hipgui.c widgets.c tools.c events.c create.c dragndrop.c

libhipgui_a_CFLAGS = $(CFLAGS) -DHIP_GUI_DATADIR=\"$(pkgdatadir)/libhipgui\"
LIBADD = @GTK_LIBS@

INCLUDES = @GTK_CFLAGS@

endif

install:
	$(install_sh_DATA) hipmanager.png $(DESTDIR)$(datadir)/pixmaps/hipmanager.png

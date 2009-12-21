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

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPCORE_INCLUDE) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_AGENT) @GTK_CFLAGS@  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

endif

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)

install:
	$(install_sh_DATA) hipmanager.png $(DESTDIR)$(datadir)/pixmaps/hipmanager.png

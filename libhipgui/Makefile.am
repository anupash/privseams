## Makefile.am for HIP GTK GUI
AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags)

if HIP_AGENT

libhipgui_adir = $(pkgdatadir)/libhipgui

noinst_LIBRARIES = libhipgui.a

libhipgui_a_SOURCES = hipgui.c widgets.c tools.c events.c create.c dragndrop.c


libhipgui_a_CFLAGS = $(CFLAGS) -DHIP_GUI_DATADIR=\"$(pkgdatadir)/libhipgui\"
LIBADD = @GTK_LIBS@
#libhipgui_a_CFLAGS = $(CFLAGS) -DHIP_GUI_DATADIR=\"$(pkgdatadir)/libhipgui\"

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_AGENT) @GTK_CFLAGS@

endif

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)


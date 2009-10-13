## Makefile.am for HIP GTK GUI
AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

GTKLDADD = `pkg-config gtk+-2.0 --libs`

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)

install:
	$(install_sh_DATA) hipmanager.png $(DESTDIR)$(datadir)/pixmaps/hipmanager.png

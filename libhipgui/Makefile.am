## Makefile.am for HIP GTK GUI
AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags) @GTK_CFLAGS@

if HIP_AGENT

lib_LTLIBRARIES = libhipgui.la

libhipgui_la_SOURCES = hipgui.c \
                       widgets.c \
                       tools.c \
                       events.c \
                       create.c \
                       dragndrop.c

endif

# TODO seems incorrect way of doing this - Rene
install:
	$(install_sh_DATA) hipmanager.png $(DESTDIR)$(datadir)/pixmaps/hipmanager.png

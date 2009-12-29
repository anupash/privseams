AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS = $(hipl_common_cflags) @GTK_CFLAGS@

lib_LTLIBRARIES = libhipgui.la

libhipgui_la_SOURCES = hipgui.c \
                       widgets.c \
                       tools.c \
                       events.c \
                       create.c \
                       dragndrop.c

# TODO seems incorrect way of doing this - Rene
install:
	$(install_sh_DATA) hipmanager.png $(DESTDIR)$(datadir)/pixmaps/hipmanager.png

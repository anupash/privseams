AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

lib_LTLIBRARIES = libhipgui.la

# NOTE: this would overwrite AM_CFLAGS, so we need to append it
libhipgui_la_CFLAGS = @GTK_CFLAGS@ @AM_CFLAGS@

libhipgui_la_SOURCES = hipgui.c \
                       widgets.c \
                       tools.c \
                       events.c \
                       create.c \
                       dragndrop.c

# TODO seems incorrect way of doing this - Rene
install:
	$(install_sh_DATA) hipmanager.png $(DESTDIR)$(datadir)/pixmaps/hipmanager.png

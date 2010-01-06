AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

lib_LTLIBRARIES = libhipopendht.la

# NOTE: this would overwrite AM_CFLAGS, so we need to append it
libhipopendht_la_CFLAGS = `xml2-config --cflags` @AM_CFLAGS@

libhipopendht_la_SOURCES = libhipopendht.c \
                           libhipopendhtxml.c

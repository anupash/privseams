AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libopphip.la

# Original sources
libopphip_la_SOURCES  = wrap.c wrap_db.c

include_HEADERS=wrap_db.h

# HIP additions to the flags.
INCLUDES = $(hipl_common_include_paths) -I$(top_srcdir)/libinet6/include
CFLAGS = $(hipl_common_cflags) -pthread

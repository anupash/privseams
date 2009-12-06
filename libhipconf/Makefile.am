AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libhipconf.la

# Original sources
libhipconf_la_SOURCES  = hipconf.c

include_HEADERS=hipconf.h

# HIP additions to the flags.
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_HIPD)
CFLAGS = $(hipl_common_cflags)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
CFLAGS += -DHIPL_DEFAULT_PREFIX=\"$(prefix)\"
CFLAGS += -Werror
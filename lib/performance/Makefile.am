# Author: Tobias Heer, heer@cs.rwth-aachen.de
AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags) -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
#CFLAGS += `pkg-config --cflags --libs glib-2.0` 
#CFLAGS += `pkg-config --cflags --libs gthread-2.0`
#CFLAGS += `pkg-config --cflags`


include_HEADERS =  performance.h


INCLUDES = $(hipl_common_include_paths)

if HIP_PERFORMANCE

lib_LTLIBRARIES = libperformance.la
libperformance_la_SOURCES = performance.c


LDADD  = ../libinet6/.libs/libinet6.a
LDADD += ../libhiptool/.libs/libhiptool.a


endif

tags:
	etags $(performance_SOURCES) $(include_HEADERS)

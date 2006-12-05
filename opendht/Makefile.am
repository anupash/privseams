AUTOMAKE_OPTIONS = foreign

XMLL = $(shell xml2-config --libs)
XMLI = $(shell xml2-config --cflags)

CFLAGS= $(hipl_common_cflags) $(XMLI)
opendhtteststub_LDFLAGS= -lhipopendht -lcrypto $(XMLL) 

INCLUDES = $(hipl_common_include_paths)
include_HEADERS = libhipopendht.h libhipopendhtxml.h

lib_LTLIBRARIES = libhipopendht.la
libhipopendht_la_SOURCES = libhipopendht.c libhipopendhtxml.c

bin_PROGRAMS = opendhtteststub
opendhtteststub_SOURCES = opendhtteststub.c
opendhtteststub_LDADD = .libs/libhipopendht.a


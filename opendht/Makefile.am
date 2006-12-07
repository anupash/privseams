AUTOMAKE_OPTIONS = foreign

XMLL = $(shell xml2-config --libs)
XMLI = $(shell xml2-config --cflags)

CFLAGS= $(hipl_common_cflags) $(XMLI) -DHIP_UNITTEST_MODE -L$(HIPL_LIBINET6_LIB)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

opendhtteststub_LDFLAGS= -lhipopendht -lcrypto -lhiptool $(XMLL) 

include_HEADERS = libhipopendht.h libhipopendhtxml.h

LDADD  = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a

lib_LTLIBRARIES = libhipopendht.la
libhipopendht_la_SOURCES = libhipopendht.c libhipopendhtxml.c

bin_PROGRAMS = opendhtteststub
opendhtteststub_SOURCES = opendhtteststub.c
opendhtteststub_LDADD = .libs/libhipopendht.a


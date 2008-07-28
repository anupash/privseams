AUTOMAKE_OPTIONS = foreign

CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI) -DHIP_UNITTEST_MODE -L$(HIPL_LIBINET6_LIB)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

include_HEADERS = libhipopendht.h libhipopendhtxml.h
LDFLAGS= @LDFLAGS@ -lcrypto $(HIP_XMLL) 

LDADD  = ../libinet6/.libs/libinet6.a
if HIP_CORPORATE
  LDADD += -lhiptool
else
  LDADD += ../libhiptool/.libs/libhiptool.a
endif

lib_LTLIBRARIES = libhipopendht.la

libhipopendht_la_SOURCES = libhipopendht.c libhipopendhtxml.c


AUTOMAKE_OPTIONS = foreign

XML_CFLAGS = `xml2-config --cflags`

# TODO check whether $(OPENWRT) is need and if yes, if we can do it differently
CFLAGS = $(hipl_common_cflags) $(XML_CFLAGS) $(OPENWRT)

lib_LTLIBRARIES = libhipopendht.la

libhipopendht_la_SOURCES = libhipopendht.c libhipopendhtxml.c

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS = $(hipl_common_cflags)

lib_LTLIBRARIES = libhiptool.la

libhiptool_la_SOURCES = crypto.c \
                        pk.c \
                        nlink.c \
                        lutil.c

if HIP_PFKEY
else
libhiptool_la_SOURCES += xfrmapi.c
endif

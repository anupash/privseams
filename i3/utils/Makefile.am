AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS= $(hipl_common_cflags)

noinst_LIBRARIES = libutils.a

libutils_a_SOURCES = byteorder.c \
                     eprintf.c \
                     gen_utils.c \
                     inetfns.c \
                     event.c \
                     netwrap_posix.c

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS= $(hipl_common_cflags)

noinst_LIBRARIES = libaes.a

libaes_a_SOURCES = aescrypp.c \
                   aescrypt.c \
                   aeshash.c \
                   aeskey.c \
                   aeskeypp.c \
                   aestab.c

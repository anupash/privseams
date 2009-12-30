AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS = $(hipl_common_cflags)

lib_LTLIBRARIES = libhipcore.la

libhipcore_la_SOURCES  = builder.c \
                         hashtable.c \
                         hashtree.c \
                         utils.c \
                         certtools.c \
                         linkedlist.c \
                         debug.c \
                         message.c \
                         esp_prot_common.c \
                         misc.c \
                         hashchain.c \
                         sqlitedbapi.c \
                         hashchain_store.c \
                         hip_statistics.c \
                         getendpointinfo.c

if HIP_PRIVSEP
libhipcore_la_SOURCES += hip_capability.c
endif

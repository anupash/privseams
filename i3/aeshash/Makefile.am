# $(PROGRAMS): $(LDEPS)

AM_CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

if HIP_HI3

noinst_LIBRARIES = libaes.a
noinst_HEADERS = aescpp.h  aes.h  aesopt.h

libaes_a_SOURCES = aescrypp.c  aescrypt.c  aeshash.c  aeskey.c \
		     aeskeypp.c  aestab.c
# aesxam.c

endif

CLEANFILES = core *.core *~
MAINTAINERCLEANFILES = Makefile.in

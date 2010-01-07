AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

lib_LTLIBRARIES = libhipsec.la

############################ NOTE ##################################
#
# Note: when you upgrade this library, please do the following:
#
# 1. uncomment policy_parse.y and policy_token.l lines
# 2. "make"
# 3. disable the policy_parse.y and policy_token.l lines again
# 4. commit the code (including lex/yacc generated c files)
#
# I could not make the lex/yacc stuff work with "make dist" which
# is mandatory for building e.g. rpm packages. -mk
####################################################################

libhipsec_la_SOURCES = ipsec_strerror.c \
                       pfkey.c \
                       #policy_parse.y \
                       #policy_token.l

AM_YFLAGS = -d -p __libhipsec
AM_LFLAGS = -P__libhipsec -olex.yy.c

BUILT_SOURCES = policy_parse.h

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
#libipsec_la_LDFLAGS = -version-info 0:1:0
#libipsec_la_LIBADD = $(LEXLIB)

#DISTCLEANFILES = policy_parse.c policy_token.c policy_token.h
DISTCLEANFILES = policy_token.h

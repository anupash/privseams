# HIP additions.
AUTOMAKE_OPTIONS = foreign
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)
CFLAGS = $(hipl_common_cflags) # -DHAVE_NETINET6_IPSEC

#bin_PROGRAMS = test-policy test-policy-priority
lib_LTLIBRARIES = libipsec.la

libipsecdir = $(includedir)/libipsec
libipsec_HEADERS = libpfkey.h

#man3_MANS = ipsec_set_policy.3 ipsec_strerror.3

#AM_CFLAGS = @GLIBC_BUGS@
AM_YFLAGS = -d -p __libipsec
AM_LFLAGS = -P__libipsec -olex.yy.c

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

libipsec_la_SOURCES =

if HIP_PFKEY
libipsec_la_SOURCES += \
  ipsec_dump_policy.c \
  ipsec_get_policylen.c \
  ipsec_strerror.c \
  key_debug.c \
  pfkey.c \
  pfkey_dump.c
#  policy_parse.y \
#  policy_token.l
endif

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
#libipsec_la_LDFLAGS = -version-info 0:0:0
#libipsec_la_LIBADD = $(LEXLIB)

noinst_HEADERS = ipsec_strerror.h policy_parse.h

#test_policy_SOURCES = test-policy.c
#test_policy_LDFLAGS = libipsec.la

#test_policy_priority_SOURCES = test-policy-priority.c
#test_policy_priority_LDFLAGS = libipsec.la

#EXTRA_DIST = ${man3_MANS} test-policy.c

DISTCLEANFILES = policy_parse.c policy_parse.h policy_token.c policy_token.h

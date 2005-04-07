#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT(hipd, main)
AC_CONFIG_SRCDIR([hipd.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_LN_S
AM_PROG_LEX
AC_PROG_YACC

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

dnl check xml2 installation
AC_CHECK_PROG(XML2_CONFIG, xml2-config, yes, no)
AC_CHECK_LIB([netlink], [rtnl_open])
AC_CHECK_LIB([crypto], [DSA_generate_key])
#AC_CHECK_LIB([gcrypt], [gcry_pk_sign])

if test x$XML2_CONFIG = xno
then
        AC_MSG_ERROR("Could not find xml2-config. libxml2 must be installed.")
fi

AC_MSG_CHECKING("XML2 libs")
XML2_LIBS=`xml2-config --libs`
LIBS="$LIBS $XML2_LIBS"
AC_MSG_RESULT(yes)

AC_MSG_CHECKING("XML2 cflags")
XML2_CFLAGS=`xml2-config --cflags`
CFLAGS="$CFLAGS $XML2_CFLAGS"
CPPFLAGS="$CPPFLAGS $XML2_CFLAGS"
LDFLAGS="${LDFLAGS}"
AC_MSG_RESULT(yes)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T

# Checks for library functions.
#AC_CHECK_LIB([crypto], [DSA_generate_key])
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset mkdir strdup strerror gethostname])
#AC_CONFIG_SUBDIRS([keynote i3])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT


#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT(USAGI-libinet6, s20041011, usagi-users@linux-ipv6.org)
AC_CONFIG_SRCDIR([cmsg_nxthdr.c])
AM_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE(cmsg_nxthdr.c, 0.1)
AC_PREFIX_DEFAULT(/usr/local/v6)

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LN_S
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([crypto], [DSA_generate_key])
AM_PROG_LIBTOOL

# Checks for header files.
AC_FUNC_ALLOCA
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_PROG_GCC_TRADITIONAL
AC_CHECK_FUNCS([bzero gethostbyaddr gethostbyname gethostname memmove memset socket strchr strerror strstr strtol strtoul uname])

AC_MSG_CHECKING([for glibc version])
AC_EGREP_CPP(%%%yes%%%, [
#include <features.h>
#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ == 1
%%%yes%%%
#endif
],[
	glibc_version=2.1
	usagi_libc=21
],[
	AC_EGREP_CPP(%%%yes%%%, [
#include <features.h>
#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ == 2
%%%yes%%%
#endif
	],[
		glibc_version=2.2
		usagi_libc=22
	],[
		AC_EGREP_CPP(%%%yes%%%, [
#include <features.h>
#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ == 3
%%%yes%%%
#endif
		],[
			glibc_version=2.3
			usagi_libc=23
		],[
			glibc_version=unknown
			usagi_libc=unknown
		])
	])
])
AC_MSG_RESULT($glibc_version)
if test x"$glibc_version" = x"unknown"; then
	echo "Fatal, abort."
	exit 1
fi
AC_SUBST(usagi_libc)

AC_CONFIG_FILES([Makefile
                 include_glibc21/Makefile
                 include_glibc22/Makefile
                 include_glibc23/Makefile])
AC_OUTPUT

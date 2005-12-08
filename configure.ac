#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Generated with autoscan and manually edited -Miika

AC_PREREQ(2.53)
AC_INIT(hipl, main, hipl-users@freelists.org, hipl--main--2.6.tar.gz)
AC_CONFIG_SRCDIR([tools/hipconf.c])
AM_INIT_AUTOMAKE(hipl, main)

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_YACC
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.
AM_PROG_LIBTOOL
AC_CHECK_LIB([c], [__libc_main])
AC_CHECK_LIB([crypto], [DSA_generate_key])
#AC_CHECK_LIB([gcrypt], [gcry_pk_sign])
AC_HEADER_SYS_WAIT
# Checks for header files.
AC_HEADER_STDC

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h locale.h malloc.h netdb.h netinet/in.h paths.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h sys/vfs.h syslog.h termios.h unistd.h utime.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_STRUCT_TM
AC_C_VOLATILE
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_GETPGRP
AC_PROG_GCC_TRADITIONAL
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETPGRP
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_STRNLEN
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit bzero dup2 floor getcwd gethostbyaddr gethostbyname gethostname getpagesize getpass gettimeofday inet_ntoa isascii memchr memmove memset mkdir munmap next_dev pathconf regcomp rmdir select setenv setlocale socket strcasecmp strchr strcspn strdup strerror strncasecmp strndup strpbrk strrchr strspn strstr strtol strtoul uname utime ipq_create_handle])

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
                libhiptool/Makefile
                libinet6/Makefile
                libinet6/include_glibc21/Makefile
                libinet6/include_glibc22/Makefile
                libinet6/include_glibc23/Makefile
                tools/Makefile
                hipd/Makefile
		firewall/Makefile
                test/Makefile])
AC_OUTPUT

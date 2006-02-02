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
AC_CHECK_LIB(crypto, DSA_generate_key,, AC_MSG_ERROR(openssl lib not found))
#AC_CHECK_LIB([gcrypt], [gcry_pk_sign])
AC_HEADER_SYS_WAIT
# Checks for header files.
AC_HEADER_STDC

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h locale.h malloc.h netdb.h netinet/in.h paths.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h sys/vfs.h syslog.h termios.h unistd.h utime.h utmp.h openssl/dsa.h])

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
AC_FUNC_ALLOCA
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
AC_CHECK_FUNCS([atexit bzero dup2 floor getcwd gethostbyaddr gethostbyname gethostname getpagesize getpass gettimeofday inet_ntoa isascii memchr memmove memset mkdir munmap next_dev pathconf regcomp rmdir select setenv setlocale socket strcasecmp strchr strcspn strdup strerror strncasecmp strndup strpbrk strrchr strspn strstr strtol strtoul uname utime])

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

hipl_opt_build=

AC_ARG_ENABLE(firewall,
              [  --enable-firewall compile HIP enabled firewall daemon],
	      [echo "checking for firewall... yes"],
              [echo "checking for firewall... no"])
if test x"$enable_firewall" = x"yes"; then
        AC_CHECK_LIB(ipq, ipq_create_handle,, AC_MSG_ERROR(libipq not found))
        AC_CHECK_LIB(glib-2.0, g_list_append,, AC_MSG_ERROR(glib not found))
# Do not work -mk
#        AC_CHECK_HEADERS(glib-2.0/glib/glist.h,,
#                         AC_MSG_ERROR(glibc development headers missing))
#        AC_CHECK_HEADERS(libipq.h,,
#                         AC_MSG_ERROR(libipq development headers missing))
        AC_DEFINE(CONFIG_HIP_FIREWALL)
        hipl_opt_build="$hipl_opt_build firewall"
fi

AC_ARG_ENABLE(agent,
              [  --enable-agent compile HIP user agent],
             [echo "checking for agent... yes"],
              [echo "checking for agent... no"])
if test x"$enable_agent" = x"yes"; then
# XX TODO: invoke "wx-config --cflags" and check that e.g. wx/menu.h exists
# XX TODO: when wxgtk 2.6.2 ends in normal distros, replace with LIB_CHECK etc
        AC_DEFINE(CONFIG_HIP_AGENT)
        hipl_opt_build="$hipl_opt_build libhipgui agent"
        
	if ! type wx-config >/dev/null; then
	   AC_MSG_ERROR([wx-config not found (install wxgtk > 2.6.2)])
        fi
	if test `wx-config --version|tr . 0` -lt 20602; then
	   AC_MSG_ERROR([wx library is too old (< 2.6.2)])
	fi
fi

AC_ARG_ENABLE(rvs,
              [  --enable-rvs compile HIP rendezvous extensions],
             [echo "checking for rvs... yes"],
              [echo "checking for rvs... no"])
if test x"$enable_rvs" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_RVS)
fi

AC_ARG_ENABLE(hi3,
              [  --enable-hi3 compile HIP Hi3 support],
             [echo "checking for Hi3... yes"],
              [echo "checking for Hi3... no"])
if test x"$enable_hi3" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_HI3)
fi

AC_ARG_ENABLE(hipsock,
	AC_HELP_STRING([--enable-hipsock],
                       [compile HIP kernel sockets (--enable-hipsock=yes|NO|/path/to/linux/source/tree)]),
	[ac_cv_use_hipsock=$withval], [ac_cv_use_hipsock=no])
AC_CACHE_CHECK([whether to use hipsock],
               [ac_cv_use_hipsock], [ac_cv_use_hipsock=no])
if test x"$enable_hipsock" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_SOCK)
        hipl_opt_build="$hipl_opt_build hipsock"
        AC_SUBST(HIPL_KERNEL_SRC, "/usr/src/linux")
elif test x"$enable_hipsock" = x"no"; then
        AC_SUBST(HIPL_KERNEL_SRC, "/dev/null")
else
        AC_DEFINE(CONFIG_HIP_SOCK)
        hipl_opt_build="$hipl_opt_build hipsock"
        AC_SUBST(HIPL_KERNEL_SRC, "$enable_hipsock")
fi

AC_SUBST(hipl_opt_build)

# Some default settings (could be detected also with AC_ARG_ENABLE)
AC_DEFINE(HIP_LOGFMT_LONG)
AC_DEFINE(CONFIG_HIP_DEBUG)
AC_SUBST(GDB_CFLAG, "-g")

# Path definitions
AC_SUBST(HIPL, `pwd`)
AC_SUBST(HIPL_TOOLS, "$HIPL/tools")
AC_SUBST(HIPL_HIPD, "$HIPL/hipd")
AC_SUBST(HIPL_FIREWALL, "$HIPL/firewall")
AC_SUBST(HIPL_LIBINET6, "$HIPL/libinet6")
AC_SUBST(HIPL_LIBINET6_LIB, "$HIPL_LIBINET6/.libs")
AC_SUBST(HIPL_LIBINET6_LIB_STATIC, "$HIPL_LIBINET6_LIB/libinet6.a")
AC_SUBST(HIPL_LIBINET6_LIB_DYNAMIC, "$HIPL_LIBINET6_LIB/libinet6.so")
AC_SUBST(HIPL_LIBINET6_INCLUDE, "$HIPL_LIBINET6/include")
AC_SUBST(HIPL_LIBHIPTOOL, "$HIPL/libhiptool")
AC_SUBST(HIPL_AGENT, "$HIPL/agent")
AC_SUBST(HIPL_LIBHIPGUI, "$HIPL/libhipgui")

AC_SUBST(hipl_common_include_paths, "-I $HIPL -I $HIPL_HIPD -I $HIPL_LIBINET6 -I $HIPL_LIBHIPTOOL -I $HIPL_TOOLS")
AC_SUBST(hipl_common_cflags, "$GDB_CFLAG")

AC_CONFIG_FILES([ Makefile
                  libhiptool/Makefile
                  libinet6/Makefile
                  libinet6/include_glibc21/Makefile
                  libinet6/include_glibc22/Makefile
                  libinet6/include_glibc23/Makefile
                  tools/Makefile
                  hipd/Makefile
                  test/Makefile
                  firewall/Makefile
                  libhipgui/Makefile
                  agent/Makefile
                  hipsock/Makefile])
AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT
AC_CONFIG_SRCDIR([cookietest.c])
AM_INIT_AUTOMAKE(hiptest, 1.3.11)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CXX
AC_PROG_GCC_TRADITIONAL

# Checks for libraries.
AC_CHECK_LIB([crypto], [DSA_generate_key])
#AC_CHECK_LIB([inet6], [getaddrinfo])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h paths.h stddef.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h termios.h unistd.h utmp.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SETPGRP
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_GETPGRP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME

AC_CHECK_FUNCS([bzero dup2 gethostbyname gethostname getpass gettimeofday inet_ntoa isascii memset mkdir select setenv socket strcasecmp strchr strdup strerror strncasecmp strrchr strtol uname])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

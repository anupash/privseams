#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT(hipl-tools, main)
AC_CONFIG_SRCDIR([hipconf.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T

# Needed for linking the shared file builder.c
AC_PROG_LN_S

# Checks for library functions.
AC_CHECK_LIB([crypto], [DSA_generate_key])
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset mkdir strdup strerror gethostname])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

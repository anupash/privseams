#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Generated with autoscan and manually edited -Miika

AC_INIT(hipl, main, hipl-users@freelists.org, hipl-main.tar.gz)
AC_CONFIG_SRCDIR([tools/hipconftool.c])
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
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
#AC_FUNC_STRNLEN
AC_CHECK_FUNCS([atexit bzero dup2 floor getcwd gethostbyaddr gethostbyname gethostname getpagesize getpass gettimeofday inet_ntoa isascii memchr memmove memset mkdir munmap next_dev pathconf regcomp rmdir select setenv setlocale socket strcasecmp strchr strcspn strdup strerror strncasecmp strndup strpbrk strrchr strspn strstr strtol strtoul uname utime])

glibc_version=2.3
usagi_libc=23
AC_SUBST(usagi_libc)

#hipl_opt_build=

AC_ARG_ENABLE(firewall,
             AC_HELP_STRING([--enable-firewall],
                            [HIP enabled firewall daemon (default is NO)]),
             [ac_cv_use_firewall=$enableval], [ac_cv_use_firewall=no])
AC_CACHE_CHECK([whether to use firewall],
               [ac_cv_use_firewall], [ac_cv_use_firewall=no])
if test x"$ac_cv_use_firewall" = x"yes"; then
        AC_CHECK_LIB(ipq, ipq_create_handle,, AC_MSG_ERROR(libipq not found))
        AC_CHECK_LIB(glib-2.0, g_list_append,, AC_MSG_ERROR(glib not found))
# Do not work -mk
#        AC_CHECK_HEADERS(glib-2.0/glib/glist.h,,
#                         AC_MSG_ERROR(glibc development headers missing))
#        AC_CHECK_HEADERS(libipq.h,,
#                         AC_MSG_ERROR(libipq development headers missing))
        AC_DEFINE(CONFIG_HIP_FIREWALL, AC_PREREQ(2.53))
#        hipl_opt_build="$hipl_opt_build firewall"
fi
AM_CONDITIONAL(HIP_FIREWALL, test x"$ac_cv_use_firewall" = x"yes")


# Try to automatically detect GTK if not disabled or enabled by user
PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.10.0, ac_cv_use_agent=yes, ac_cv_use_agent=no)
if test x"$ac_cv_use_agent" = x"no"; then
	PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.8.0, ac_cv_use_agent=yes, ac_cv_use_agent=no)
	if test x"$ac_cv_use_agent" = x"yes"; then
		AC_MSG_WARN(You are missing >= GTK 2.10, it is VERY recommended)
	fi
fi

AC_ARG_ENABLE(agent,
              AC_HELP_STRING([--enable-agent],
              [HIP user agent]),
              [ac_cv_use_agent=$enableval],)
AC_CACHE_CHECK([whether to use agent],
               [ac_cv_use_agent], [ac_cv_use_agent=yes])
if test x"$ac_cv_use_agent" = x"yes"; then
	AC_DEFINE(CONFIG_HIP_AGENT, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_AGENT, test x"$ac_cv_use_agent" = x"yes")

AC_ARG_ENABLE(hi3,
             AC_HELP_STRING([--enable-hi3],
                            [Hi3 support (default is NO)]),
             [ac_cv_use_hi3=$enableval], [ac_cv_use_hi3=no])
AC_CACHE_CHECK([whether to use hi3],
               [ac_cv_use_hi3], [ac_cv_use_hi3=no])
if test x"$ac_cv_use_hi3" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_HI3, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_HI3, test x"$ac_cv_use_hi3" = x"yes")

AC_ARG_ENABLE(lsi,
             AC_HELP_STRING([--enable-lsi],
                            [LSI support (default is NO)]),
             [ac_cv_use_lsi=$enableval], [ac_cv_use_lsi=no])
AC_CACHE_CHECK([whether to use lsi],
               [ac_cv_use_lsi], [ac_cv_use_lsi=no])
if test x"$ac_cv_use_lsi" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_LSI, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_LSI, test x"$ac_cv_use_lsi" = x"yes")

AC_ARG_ENABLE(cookie,
             AC_HELP_STRING([--enable-cookie],
                            [HIP cookie extensions (default is NO)]),
             [ac_cv_use_cookie=$enableval], [ac_cv_use_cookie=no])
AC_CACHE_CHECK([whether to use cookie extensions],
               [ac_cv_use_cookie], [ac_cv_use_cookie=no])
if test x"$ac_cv_use_cookie" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_COOKIE, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(corporate,
             AC_HELP_STRING([--enable-corporate],
                            [HIP corporate extensions (default is NO)]),
             [ac_cv_use_corporate=$enableval], [ac_cv_use_corporate=no])
AC_CACHE_CHECK([whether to use corporate extensions],
               [ac_cv_use_corporate], [ac_cv_use_corporate=no])
if test x"$ac_cv_use_corporate" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_CORPORATE, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_CORPORATE, test x"$ac_cv_use_corporate" = x"yes")

AC_ARG_ENABLE(pfkey,
             AC_HELP_STRING([--enable-pfkey],
                            [HIP pfkey extensions (default is NO)]),
             [ac_cv_use_pfkey=$enableval], [ac_cv_use_pfkey=no])
AC_CACHE_CHECK([whether to use pfkey extensions],
               [ac_cv_use_pfkey], [ac_cv_use_pfkey=no])
if test x"$ac_cv_use_pfkey" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PFKEY, AC_PREREQ(2.53))
        AM_PROG_LEX
fi
AM_CONDITIONAL(HIP_PFKEY, test x"$ac_cv_use_pfkey" = x"yes")

AC_ARG_ENABLE(cert,
             AC_HELP_STRING([--enable-cert],
                            [Samu's cert extensions (default is NO)]),
             [ac_cv_use_cert=$enableval], [ac_cv_use_cert=no])
AC_CACHE_CHECK([whether to use cert extensions],
               [ac_cv_use_cert], [ac_cv_use_cert=no])
if test x"$ac_cv_use_cert" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_CERT, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(rvs,
             AC_HELP_STRING([--enable-rvs],
                            [HIP Rendezvous Extensions (default is YES)]),
             [ac_cv_use_rvs=$enableval], [ac_cv_use_rvs=yes])
AC_CACHE_CHECK([whether to use RVS],
               [ac_cv_use_rvs], [ac_cv_use_rvs=yes])
if test x"$ac_cv_use_rvs" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_RVS, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(buggyipsec,
             AC_HELP_STRING([--enable-buggyipsec],
                            [Support for IPsec in older kernels (default is NO)]),
             [ac_cv_use_buggyipsec=$enableval], [ac_cv_use_buggyipsec=no])
AC_CACHE_CHECK([whether to use buggyipsec],
               [ac_cv_use_buggyipsec], [ac_cv_use_buggyipsec=no])
if test x"$ac_cv_use_buggyipsec" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_BUGGYIPSEC, AC_PREREQ(2.53))
fi

AM_CONDITIONAL(HIP_PRIVSEP, test x"$ac_cv_use_privsep" = x"yes")
AC_ARG_ENABLE(privsep,
             AC_HELP_STRING([--enable-privsep],
                            [Privilege separation (default is NO)]),
             [ac_cv_use_privsep=$enableval], [ac_cv_use_privsep=no])
AC_CACHE_CHECK([whether to use privsep],
               [ac_cv_use_privsep], [ac_cv_use_privsep=no])
if test x"$ac_cv_use_privsep" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PRIVSEP, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_PRIVSEP, test x"$ac_cv_use_privsep" = x"yes")

AC_ARG_ENABLE(escrow,
             AC_HELP_STRING([--enable-escrow],
                            [HIP IPsec escrow (default is NO)]),
             [ac_cv_use_escrow=$enableval], [ac_cv_use_escrow=no])
AC_CACHE_CHECK([whether to use ESCROW],
               [ac_cv_use_escrow], [ac_cv_use_escrow=no])
if test x"$ac_cv_use_escrow" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ESCROW, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(opportunistic,
             AC_HELP_STRING([--enable-opportunistic],
                            [HIP opportunistic extensions (default is YES)]),
             [ac_cv_use_opportunistic=$enableval], [ac_cv_use_opportunistic=yes])
AC_CACHE_CHECK([whether to use opportunistic],
               [ac_cv_use_opportunistic], [ac_cv_use_opportunistic=yes])
if test x"$ac_cv_use_opportunistic" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPPORTUNISTIC, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_OPPORTUNISTIC, test x"$ac_cv_use_opportunistic" = x"yes")

AC_ARG_ENABLE(opendht,
             AC_HELP_STRING([--enable-opendht],
                            [OpenDHT support (default is YES)]),
             [ac_cv_use_opendht=$enableval], [ac_cv_use_opendht=yes])
AC_CACHE_CHECK([whether to use opendht],
               [ac_cv_use_opendht], [ac_cv_use_opendht=yes])
if test x"$ac_cv_use_opendht" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPENDHT, AC_PREREQ(2.53))
        AC_CHECK_LIB(xml2, xmlFreeDoc,, AC_MSG_ERROR(libxml2 not found))
        #AC_CHECK_PROG(RPCGEN, rpcgen,,)
fi
AM_CONDITIONAL(HIP_OPENDHT, test x"$ac_cv_use_opendht" = x"yes")

AC_ARG_ENABLE(blind,
             AC_HELP_STRING([--enable-blind],
                            [HIP BLIND extensions (default is NO)]),
             [ac_cv_use_blind=$enableval], [ac_cv_use_blind=no])
AC_CACHE_CHECK([whether to use BLIND],
               [ac_cv_use_blind], [ac_cv_use_blind=no])
if test x"$ac_cv_use_blind" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_BLIND, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(debug,
             AC_HELP_STRING([--enable-debug],
                            [Enable debug (default is YES)]),
             [ac_cv_use_debug=$enableval],
             [ac_cv_use_debug=yes])
AC_CACHE_CHECK([whether to have verbose debug],
               [ac_cv_use_debug], [ac_cv_use_debug=yes])
if test x"$ac_cv_use_debug" = x"yes"; then
        AC_DEFINE(HIP_LOGFMT_LONG, AC_PREREQ(2.53))
	AC_DEFINE(CONFIG_HIP_DEBUG, AC_PREREQ(2.53))
	AC_SUBST(GDB_CFLAG, "-g")
fi

# Path definitions
AC_SUBST(HIPL, `pwd`)
AC_SUBST(HIPL_TOOLS, "$HIPL/tools")
AC_SUBST(HIPL_HIPD, "$HIPL/hipd")
AC_SUBST(HIPL_FIREWALL, "$HIPL/firewall")
AC_SUBST(HIPL_LIBIPSEC, "$HIPL/libipsec")
AC_SUBST(HIPL_LIBINET6, "$HIPL/libinet6")
AC_SUBST(HIPL_LIBINET6_LIB, "$HIPL_LIBINET6/.libs")
AC_SUBST(HIPL_LIBINET6_LIB_STATIC, "$HIPL_LIBINET6_LIB/libinet6.a")
AC_SUBST(HIPL_LIBINET6_LIB_DYNAMIC, "$HIPL_LIBINET6_LIB/libinet6.so")
AC_SUBST(HIPL_LIBINET6_INCLUDE, "$HIPL_LIBINET6/include")
AC_SUBST(HIPL_LIBOPPHIP, "$HIPL/libopphip")
AC_SUBST(HIPL_LIBOPPHIP_LIB, "$HIPL_LIBOPPHIP/.libs")
AC_SUBST(HIPL_LIBOPPHIP_LIB_STATIC, "$HIPL_LIBOPPHIP_LIB/libinet6.a")
AC_SUBST(HIPL_LIBOPPHIP_LIB_DYNAMIC, "$HIPL_LIBOPPHIP_LIB/libinet6.so")
AC_SUBST(HIPL_LIBHIPTOOL, "$HIPL/libhiptool")
AC_SUBST(HIPL_LIBHIPTOOL_LIB, "$HIPL_LIBHIPTOOL/.libs")
AC_SUBST(HIPL_LIBHIPTOOL_LIB_STATIC, "$HIPL_LIBHIPTOOL_LIB/libhiptool.a")
AC_SUBST(HIPL_LIBHIPTOOL_LIB_DYNAMIC, "$HIPL_LIBHIPTOOL_LIB/libhiptool.so")
AC_SUBST(HIPL_AGENT, "$HIPL/agent")
AC_SUBST(HIPL_LIBHIPGUI, "$HIPL/libhipgui")
AC_SUBST(HIPL_OPENDHT, "$HIPL/opendht")
AC_SUBST(HIPL_XMLL, `xml2-config --libs`)
AC_SUBST(HIPL_XMLI, `xml2-config --cflags`)
AC_PREFIX_DEFAULT("/usr/local")

AC_SUBST(hipl_common_include_paths, "-I $HIPL -I $HIPL_HIPD -I $HIPL_LIBINET6 -I $HIPL_LIBHIPTOOL -I$HIPL_LIBOPPHIP -I $HIPL_TOOLS -I $HIPL_OPENDHT -I $HIPL_LIBIPSEC")
AC_SUBST(hipl_common_cflags, "$GDB_CFLAG $XMLI")

AC_CONFIG_FILES([ Makefile
                  libhiptool/Makefile
                  libinet6/Makefile
                  libinet6/include_glibc21/Makefile
                  libinet6/include_glibc22/Makefile
                  libinet6/include_glibc23/Makefile
                  libopphip/Makefile
                  opendht/Makefile
                  tools/Makefile
                  hipd/Makefile
                  test/Makefile
                  firewall/Makefile
                  libhipgui/Makefile
                  agent/Makefile
		  libipsec/Makefile])
AC_OUTPUT


#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Generated with autoscan and manually edited -Miika

AC_INIT(hipl, main, hipl-users@freelists.org, hipl-main.tar.gz)
AC_CONFIG_SRCDIR([tools/hipconftool.c])
AM_INIT_AUTOMAKE(hipl, main)

# Checks for programs.
#AC_PROG_CXX
AC_PROG_AWK
AC_PROG_YACC
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Check for python for tools directory
AM_PATH_PYTHON([2.4.3],, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

# Checks for libraries.
AM_PROG_LIBTOOL
AC_CHECK_LIB(crypto, DSA_generate_key,, AC_MSG_ERROR(openssl lib not found))
# We need the math lib in the registration extension.
AC_CHECK_LIB(m, pow,, AC_MSG_ERROR(Math lib not found))
#AC_CHECK_LIB(uuid, uuid_generate,, AC_MSG_ERROR(Uuid lib not found))
AC_CHECK_LIB(uuid,uuid_generate,[ac_has_uuid_lib=1])
#AC_CHECK_LIB([gcrypt], [gcry_pk_sign])
#AC_CHECK_LIB([pthread], [sem_open])
AC_CHECK_LIB(config, config_setting_index,, [AC_MSG_WARN([libconfig not found, using default configuration of esp token extension])])
AC_HEADER_SYS_WAIT
# Checks for header files.
AC_HEADER_STDC

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h locale.h malloc.h netdb.h netinet/in.h paths.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h sys/vfs.h syslog.h termios.h unistd.h utime.h utmp.h openssl/dsa.h])

case "$host" in
  alpha*)
    TARGET=ALPHA;
    ;;
  arm*)
    TARGET=ARM;
    ;;
  hppa*linux* | parisc*linux*)
    TARGET=PA_LINUX;
    ;;
  i?86*)
    TARGET=X86;
    ;;
  ia64*)
    TARGET=IA64;
    ;;
  mips*linux*)
    TARGET=MIPS_LINUX;
    ;;
  powerpc*linux*)
    TARGET=POWERPC;
    ;;
  x86_64*)
    TARGET=X86_64;
    ;;
esac

AC_SUBST(TARGET)

case "$host" in
  alpha*)
    TARGET=ALPHA;
    ;;
  arm*)
    TARGET=ARM;
    ;;
  hppa*linux* | parisc*linux*)
    TARGET=PA_LINUX;
    ;;
  i?86*)
    TARGET=X86;
    ;;
  ia64*)
    TARGET=IA64;
    ;;
  mips*linux*)
    TARGET=MIPS_LINUX;
    ;;
  powerpc*linux*)
    TARGET=POWERPC;
    ;;
  x86_64*)
    TARGET=X86_64;
    ;;
esac

AC_SUBST(TARGET)

# Checks for typedefs, structures, and compiler characteristics.
#AC_C_CONST
#AC_TYPE_UID_T
#AC_C_INLINE
#AC_TYPE_MODE_T
#AC_TYPE_OFF_T
#AC_TYPE_PID_T
#AC_TYPE_SIZE_T
#AC_CHECK_MEMBERS([struct stat.st_blksize])
#AC_STRUCT_ST_BLOCKS
#AC_CHECK_MEMBERS([struct stat.st_rdev])
#AC_HEADER_TIME
#AC_STRUCT_TM
#AC_C_VOLATILE
#AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
#AC_FUNC_FORK
#AC_FUNC_CHOWN
#AC_FUNC_CLOSEDIR_VOID
#AC_FUNC_ERROR_AT_LINE
#AC_FUNC_GETPGRP
#AC_PROG_GCC_TRADITIONAL
#AC_HEADER_MAJOR
#AC_FUNC_ALLOCA
#AC_FUNC_MALLOC
#AC_FUNC_MEMCMP
#AC_FUNC_MKTIME
#AC_FUNC_MMAP
#AC_FUNC_REALLOC
#AC_FUNC_SELECT_ARGTYPES
#AC_FUNC_SETPGRP
#AC_TYPE_SIGNAL
#AC_FUNC_STAT
#AC_FUNC_STRFTIME
#AC_FUNC_UTIME_NULL
#AC_FUNC_VPRINTF
#AC_FUNC_STRNLEN
#AC_CHECK_FUNCS([atexit bzero dup2 floor getcwd gethostbyaddr gethostbyname gethostname getpagesize getpass gettimeofday inet_ntoa isascii memchr memmove memset mkdir munmap next_dev pathconf regcomp rmdir select setenv setlocale socket strcasecmp strchr strcspn strdup strerror strncasecmp strndup strpbrk strrchr strspn strstr strtol strtoul uname utime])

dnl Default sysconf and lockfile directory
dnl TODO: @Miika is there any better way to define this?
AC_SUBST(sysconfdir, /etc/hip/)
AC_DEFINE_UNQUOTED(HIPL_SYSCONFDIR, "$(eval echo $sysconfdir)")
AH_TEMPLATE(HIPL_SYSCONFDIR, [default configuration file location])

AC_SUBST(lockdir, /var/lock/)
AC_DEFINE_UNQUOTED(HIPL_LOCKDIR, "$(eval echo $lockdir)")
AH_TEMPLATE(HIPL_LOCKDIR, [default lock file location])


glibc_version=2.3
usagi_libc=23
AC_SUBST(usagi_libc)

#hipl_opt_build=

AC_ARG_ENABLE(firewall,
             AC_HELP_STRING([--enable-firewall],
                            [HIP enabled firewall daemon (default is YES)]),
             [ac_cv_use_firewall=$enableval], [ac_cv_use_firewall=yes])
AC_CACHE_CHECK([whether to use firewall],
               [ac_cv_use_firewall], [ac_cv_use_firewall=yes])
if test x"$ac_cv_use_firewall" = x"yes"; then
        AC_CHECK_LIB(ipq, ipq_create_handle,, AC_MSG_ERROR(libipq not found, install iptables developer headers))
#        AC_CHECK_LIB(glib-2.0, g_list_append,, AC_MSG_ERROR(glib not found))
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
        AC_CHECK_LIB(sqlite3, sqlite3_open,, AC_MSG_ERROR(libsqlite3-dev not found))	
fi
AM_CONDITIONAL(HIP_AGENT, test x"$ac_cv_use_agent" = x"yes")

AC_ARG_ENABLE(cookie,
             AC_HELP_STRING([--enable-cookie],
                            [HIP cookie extensions (default is NO)]),
             [ac_cv_use_cookie=$enableval], [ac_cv_use_cookie=no])
AC_CACHE_CHECK([whether to use cookie extensions],
               [ac_cv_use_cookie], [ac_cv_use_cookie=no])
if test x"$ac_cv_use_cookie" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_COOKIE, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(pfkey,
             AC_HELP_STRING([--enable-pfkey],
                            [HIP pfkey extensions (default is NO)]),
             [ac_cv_use_pfkey=$enableval], [ac_cv_use_pfkey=no])
AC_CACHE_CHECK([whether to use pfkey extensions],
               [ac_cv_use_pfkey], [ac_cv_use_pfkey=no])
if test x"$ac_cv_use_pfkey" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PFKEY, AC_PREREQ(2.53))
        AC_DEFINE(PATH_IPSEC_H, "netinet/ipsec.h")
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

AC_ARG_ENABLE(ice,
             AC_HELP_STRING([--enable-ice],
                            [ICE-based HIP NAT traversal extensions (default is YES)]),
             [ac_cv_use_ice=$enableval], [ac_cv_use_ice=yes])
AC_CACHE_CHECK([whether to use ICE],
               [ac_cv_use_ice], [ac_cv_use_ice=yes])
if test x"$ac_cv_use_ice" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ICE, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_ICE, test x"$ac_cv_use_ice" = x"yes")

AC_ARG_ENABLE(hipproxy,
             AC_HELP_STRING([--enable-hipproxy],
                            [HIP Proxy (default is YES)]),
             [ac_cv_use_hipproxy=$enableval], [ac_cv_use_hipproxy=yes])
AC_CACHE_CHECK([whether to use HIP proxy],
               [ac_cv_use_hipproxy], [ac_cv_use_hipproxy=yes])
if test x"$ac_cv_use_hipproxy" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_HIPPROXY, AC_PREREQ(2.53))
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

AC_ARG_ENABLE(buggyprefix,
             AC_HELP_STRING([--enable-buggyprefix],
                            [Support for kernels with flawed loopback handling (default is NO)]),
             [ac_cv_use_buggyprefix=$enableval], [ac_cv_use_buggyprefix=no])
AC_CACHE_CHECK([whether to use buggyprefix],
               [ac_cv_use_buggyprefix], [ac_cv_use_buggyprefix=no])
if test x"$ac_cv_use_buggyprefix" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_BUGGYPREFIX, AC_PREREQ(2.53))
fi

AC_ARG_ENABLE(maemo,
             AC_HELP_STRING([--enable-maemo],
                            [Maemo (default is NO)]),
             [ac_cv_use_maemo=$enableval \
	      ac_cv_use_altsep=yes \
              ac_cv_use_i3=no], [ac_cv_use_maemo=no])
AC_CACHE_CHECK([whether to use Maemo],
               [ac_cv_use_maemo], [ac_cv_use_maemo=no])
if test x"$ac_cv_use_maemo" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_MAEMO, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_MAEMO, test x"$ac_cv_use_maemo" = x"yes")

AC_ARG_ENABLE(openwrt,
             AC_HELP_STRING([--enable-openwrt],
                            [OpenWRT (default is NO)]),
             [ac_cv_use_openwrt=$enableval \
	      ac_cv_use_altsep=yes], [ac_cv_use_openwrt=no])
AC_CACHE_CHECK([whether to use OpenWRT],
               [ac_cv_use_openwrt], [ac_cv_use_openwrt=no])
if test x"$ac_cv_use_openwrt" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPENWRT, AC_PREREQ(2.53))
        AC_SUBST(OPENWRT_CFLAGS, "-lc")
        if test x"$TARGET" = x"MIPS_LINUX"; then
                AC_DEFINE(CONFIG_HIP_OPENWRT_MIPSLINUX, AC_PREREQ(2.53))
        fi
fi
AM_CONDITIONAL(HIP_OPENWRT, test x"$ac_cv_use_openwrt" = x"yes")

# if we already set altsep, then don't check the flags anymore
if test x"$ac_cv_use_altsep" != x"yes"; then
AC_ARG_ENABLE(altsep,
             AC_HELP_STRING([--enable-altsep],
                            [Alternative privilege separation (default is NO)]),
             [ac_cv_use_altsep=$enableval], [ac_cv_use_altsep=no])
fi
AC_CACHE_CHECK([whether to use Alternative privilege separation],
               [ac_cv_use_altsep], [ac_cv_use_altsep=no])
if test x"$ac_cv_use_altsep" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ALTSEP, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_ALTSEP, test x"$ac_cv_use_altsep" = x"yes")

# define this iff we have uuid lib
AM_CONDITIONAL(HIP_UUIDLIB, test "$ac_has_uuid_lib" = "1")

# if we already set i3, then don't check the flags anymore
if test x"$ac_cv_use_i3" != x"no"; then
AC_ARG_ENABLE(i3,
              AC_HELP_STRING([--enable-i3],
              [HIP i3  (default is YES)]),
              [ac_cv_use_i3=$enableval],)
fi
AC_CACHE_CHECK([whether to use i3],
               [ac_cv_use_i3], [ac_cv_use_i3=yes])
if test x"$ac_cv_use_i3" = x"yes"; then
	AC_DEFINE(CONFIG_HIP_I3, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_I3, test x"$ac_cv_use_i3" = x"yes")

AM_CONDITIONAL(HIP_PRIVSEP, test x"$ac_cv_use_privsep" = x"yes")
AC_ARG_ENABLE(privsep,
             AC_HELP_STRING([--enable-privsep],
                            [Privilege separation (default is YES)]),
             [ac_cv_use_privsep=$enableval], [ac_cv_use_privsep=yes])
AC_CACHE_CHECK([whether to use privsep],
               [ac_cv_use_privsep], [ac_cv_use_privsep=yes])
if test x"$ac_cv_use_privsep" = x"yes"; then
	if test x"$ac_cv_use_altsep" != x"yes"; then
		AC_CHECK_LIB(cap, cap_get_proc,, AC_MSG_ERROR(libcap-dev developer headers not found))
	fi
        AC_DEFINE(CONFIG_HIP_PRIVSEP, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_PRIVSEP, test x"$ac_cv_use_privsep" = x"yes")

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

AC_ARG_ENABLE(savaipopt,
             AC_HELP_STRING([--enable-savaipoption],
                            [HIP SAVA IP option extensions, if no encrypt IP address (default is YES)]),
             [ac_cv_use_savaipopt=$enableval], [ac_cv_use_savaipopt=yes])
AC_CACHE_CHECK([whether to use sava ip option],
               [ac_cv_use_savaipopt], [ac_cv_use_savaipopt=yes])
if test x"$ac_cv_use_savaipopt" = x"yes"; then
        AC_DEFINE(CONFIG_SAVAH_IP_OPTION, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(SAVAH_IP_OPTION, test x"$ac_cv_use_savaipopt" = x"yes")

AC_ARG_ENABLE(opendht,
             AC_HELP_STRING([--enable-opendht],
                            [OpenDHT support (default is YES)]),
             [ac_cv_use_opendht=$enableval], [ac_cv_use_opendht=yes])
AC_CACHE_CHECK([whether to use opendht],
               [ac_cv_use_opendht], [ac_cv_use_opendht=yes])
if test x"$ac_cv_use_opendht" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPENDHT, AC_PREREQ(2.53))
        #AC_CHECK_PROG(RPCGEN, rpcgen,,)
fi
AC_CHECK_LIB(xml2, xmlFreeDoc,, AC_MSG_ERROR(libxml2 not found))
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

AC_ARG_ENABLE(optimizations,
             AC_HELP_STRING([--enable-optimizations],
                            [GCC compiler optimizations (default is NO)]),
             [ac_cv_use_optimizations=$enableval], [ac_cv_use_optimizations=no])
AC_CACHE_CHECK([whether to use GCC optimizations],
               [ac_cv_use_optimizations], [ac_cv_use_optimizations=no])
if test x"$ac_cv_use_optimizations" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPTIMIZATIONS, AC_PREREQ(2.53))
        AC_SUBST(OPTIMIZATIONS_CFLAGS, "-O2")
fi
AM_CONDITIONAL(HIP_OPTIMIZATIONS, test x"$ac_cv_use_optimizations" = x"yes")

AC_ARG_ENABLE(profiling,
             AC_HELP_STRING([--enable-profiling],
                            [compile in gprof profiling support (default is NO)]),
             [ac_cv_use_profiling=$enableval], [ac_cv_use_profiling=no])
AC_CACHE_CHECK([whether to use grof support],
               [ac_cv_use_profiling], [ac_cv_use_profiling=no])
if test x"$ac_cv_use_profiling" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PROFILING, AC_PREREQ(2.53))
        AC_SUBST(GPROF_CFLAGS, "-pg")
fi
AM_CONDITIONAL(HIP_PROFILING, test x"$ac_cv_use_profiling" = x"yes")

AC_ARG_ENABLE(ecdsa,
             AC_HELP_STRING([--enable-ecdsa],
                            [compile in gprof ecdsa support (default is NO)]),
             [ac_cv_use_ecdsa=$enableval], [ac_cv_use_ecdsa=no])
AC_CACHE_CHECK([whether to use grof support],
               [ac_cv_use_ecdsa], [ac_cv_use_ecdsa=no])
if test x"$ac_cv_use_ecdsa" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ECDSA, AC_PREREQ(2.53))
        AC_SUBST(GPROF_CFLAGS, "-pg")
fi
AM_CONDITIONAL(HIP_ECDSA, test x"$ac_cv_use_ecdsa" = x"yes")

AC_ARG_ENABLE(measurements,
             AC_HELP_STRING([--enable-measurements],
                            [activate internal performance measurements (default is NO)]),
             [ac_cv_use_measurements=$enableval], [ac_cv_use_measurements=no])
AC_CACHE_CHECK([whether to do internal measurements],
               [ac_cv_use_measurements], [ac_cv_use_measurements=no])
if test x"$ac_cv_use_measurements" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_MEASUREMENTS, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_MEASUREMENTS, test x"$ac_cv_use_measurements" = x"yes")

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

AC_ARG_ENABLE(midauth,
             AC_HELP_STRING([--enable-midauth],
                            [Enable middlebox authentification (default is NO)]),
             [ac_cv_use_midauth=$enableval],
             [ac_cv_use_midauth=no])
AC_CACHE_CHECK([whether to have middlebox authentification],
               [ac_cv_use_midauth], [ac_cv_use_midauth=no])
if test x"$ac_cv_use_midauth" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_MIDAUTH, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_MIDAUTH, test x"$ac_cv_use_midauth" = x"yes")

AC_ARG_ENABLE(performance,
             AC_HELP_STRING([--enable-performance],
                            [Performace measurement support (default is NO)]),
             [ac_cv_use_performance=$enableval], [ac_cv_use_performance=no])
AC_CACHE_CHECK([whether to use performance measurement],
               [ac_cv_use_performance], [ac_cv_use_performance=no])
if test x"$ac_cv_use_performance" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PERFORMANCE, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_PERFORMANCE, test x"$ac_cv_use_performance" = x"yes")

AC_ARG_ENABLE(demo,
             AC_HELP_STRING([--enable-demo],
                            [Demo output (default is NO)]),
             [ac_cv_use_demo=$enableval], [ac_cv_use_demo=no])
AC_CACHE_CHECK([whether to print output for demos],
               [ac_cv_use_demo], [ac_cv_use_demo=no])
if test x"$ac_cv_use_demo" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_DEMO, AC_PREREQ(2.53))
fi
AM_CONDITIONAL(HIP_DEMO, test x"$ac_cv_use_demo" = x"yes")

AC_ARG_ENABLE(libinet6,
             AC_HELP_STRING([--enable-libinet6],
                            [Libinet6 output (default is YES)]),
             [ac_cv_use_libinet6=$enableval], [ac_cv_use_libinet6=yes])
AC_CACHE_CHECK([whether to print output for libinet6s],
               [ac_cv_use_libinet6], [ac_cv_use_libinet6=yes])
if test x"$ac_cv_use_libinet6" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_LIBINET6, AC_PREREQ(2.53))
        AC_SUBST(HIPL_LIBINET6_INCLUDE, "$HIPL_LIBINET6/include")
else
        # Can't leave this undefined, otherwise build fails.
        # "." is always in the search path, we can just add it.
        AC_SUBST(HIPL_LIBINET6_INCLUDE, ".")
fi
AM_CONDITIONAL(HIP_LIBINET6, test x"$ac_cv_use_libinet6" = x"yes")

AC_PREFIX_DEFAULT("/usr/local")

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
AC_SUBST(HIPL_LIBOPPHIP, "$HIPL/libopphip")
AC_SUBST(HIPL_LIBOPPHIP_LIB, "$HIPL_LIBOPPHIP/.libs")
AC_SUBST(HIPL_LIBOPPHIP_LIB_STATIC, "$HIPL_LIBOPPHIP_LIB/libinet6.a")
AC_SUBST(HIPL_LIBOPPHIP_LIB_DYNAMIC, "$HIPL_LIBOPPHIP_LIB/libinet6.so")
AC_SUBST(HIPL_LIBHIPTOOL, "$HIPL/libhiptool")
AC_SUBST(HIPL_LIBHIPTOOL_LIB, "$HIPL_LIBHIPTOOL/.libs")
AC_SUBST(HIPL_LIBHIPTOOL_LIB_STATIC, "$HIPL_LIBHIPTOOL_LIB/libhiptool.a")
AC_SUBST(HIPL_LIBHIPTOOL_LIB_DYNAMIC, "$HIPL_LIBHIPTOOL_LIB/libhiptool.so")
AC_SUBST(HIPL_LIBHIPCORE, "$HIPL/libhipcore")
AC_SUBST(HIPL_LIBHIPCORE_LIB, "$HIPL_LIBHIPCORE/.libs")
AC_SUBST(HIPL_LIBHIPCORE_LIB_STATIC, "$HIPL_LIBHIPCORE_LIB/libhipcore.a")
AC_SUBST(HIPL_LIBHIPCORE_LIB_DYNAMIC, "$HIPL_LIBHIPCORE_LIB/libhipcore.so")
AC_SUBST(HIPL_LIBHIPCORE_INCLUDE, "$HIPL_LIBHIPCORE")
AC_SUBST(HIPL_LIBHIPANDROID, "$HIPL/libhipandroid")
AC_SUBST(HIPL_LIBHIPCONF, "$HIPL/libhipconf")
AC_SUBST(HIPL_LIBHIPCONF_LIB, "$HIPL/libhipconf/.libs")
AC_SUBST(HIPL_AGENT, "$HIPL/agent")
AC_SUBST(HIPL_LIBHIPGUI, "$HIPL/libhipgui")
AC_SUBST(HIPL_OPENDHT, "$HIPL/libdht")
AC_SUBST(HIPL_OPENDHT_LIB, "$HIPL_OPENDHT/.libs")
AC_SUBST(HIPL_I3_CLIENT, "$HIPL/i3/i3_client")
AC_SUBST(HIPL_I3, "$HIPL/i3/i3")
AC_SUBST(HIPL_AESHASH, "$HIPL/i3/aeshash")
AC_SUBST(HIPL_I3_CHORD, "$HIPL/i3/chord")
AC_SUBST(HIPL_I3_UTILS, "$HIPL/i3/utils")
AC_SUBST(HIPL_XMLL, `xml2-config --libs`)
AC_SUBST(HIPL_XMLI, `xml2-config --cflags`)
AC_SUBST(HIPL_I3UTILS_LIB_DYNAMIC, "$HIPL_I3_UTILS/libutils.a")
AC_SUBST(HIPL_PERFORMANCE, "$HIPL/performance")
AC_SUBST(HIPL_PERFORMANCE_LIB, "HIPL_PERFORMANCE/.libs/performance.a")

AC_SUBST(hipl_common_include_paths, "-I $HIPL -I $HIPL_HIPD -I $HIPL_LIBINET6 -I $HIPL_LIBINET6_INCLUDE -I $HIPL_LIBHIPTOOL -I $HIPL_LIBHIPCORE_INCLUDE -I $HIPL_LIBOPPHIP -I $HIPL_TOOLS -I $HIPL_OPENDHT -I $HIPL_LIBIPSEC -I $HIPL_I3 -I $HIPL_I3_CLIENT -I $HIPL_AESHASH -I $HIPL_I3_CHORD -I $HIPL_I3_UTILS -I $HIPL_PERFORMANCE -I $HIPL_LIBHIPCONF")

AC_SUBST(hipl_common_cflags, "$OPENWRT_CFLAGS $GDB_CFLAG $XMLI -Werror -Wall")

AC_CONFIG_FILES([ Makefile
		  libhipcore/Makefile
                  libhiptool/Makefile
                  libinet6/Makefile
                  libinet6/include_glibc21/Makefile
                  libinet6/include_glibc22/Makefile
                  libinet6/include_glibc23/Makefile
                  libopphip/Makefile
                  libdht/Makefile
		  libhipconf/Makefile
		  i3/Makefile
  		  i3/aeshash/Makefile
		  i3/chord/Makefile
		  i3/i3/Makefile
		  i3/i3_client/Makefile
		  i3/utils/Makefile
                  tools/Makefile
                  hipd/Makefile
                  test/Makefile
                  firewall/Makefile
                  libhipgui/Makefile
                  agent/Makefile
		  libipsec/Makefile
                  hipfwmi/Makefile
		  performance/Makefile])
					
AC_OUTPUT


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
AC_CHECK_LIB(uuid, uuid_generate,, AC_MSG_ERROR(Uuid lib not found))
#AC_CHECK_LIB([gcrypt], [gcry_pk_sign])
#AC_CHECK_LIB([pthread], [sem_open])
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

AC_ARG_ENABLE(openwrt,
             AC_HELP_STRING([--enable-openwrt],
                            [OpenWRT (default is NO)]),
             [ac_cv_use_openwrt=$enableval], [ac_cv_use_openwrt=no])
AC_CACHE_CHECK([whether to use OpenWRT],
               [ac_cv_use_openwrt], [ac_cv_use_openwrt=no])
if test x"$ac_cv_use_openwrt" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPENWRT, AC_PREREQ(2.53))5B
        AC_SUBST(OPENWRT_CFLAGS, "-lc")
        if test x"$TARGET" = x"MIPS_LINUX"; then
                AC_DEFINE(CONFIG_HIP_OPENWRT_MIPSLINUX, AC_PREREQ(2.53))
        fi
fi
AM_CONDITIONAL(HIP_OPENWRT, test x"$ac_cv_use_openwrt" = x"yes")

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

AM_CONDITIONAL(HIP_PRIVSEP, test x"$ac_cv_use_privsep" = x"yes")
AC_ARG_ENABLE(privsep,
             AC_HELP_STRING([--enable-privsep],
                            [Privilege separation (default is YES)]),
             [ac_cv_use_privsep=$enableval], [ac_cv_use_privsep=yes])
AC_CACHE_CHECK([whether to use privsep],
               [ac_cv_use_privsep], [ac_cv_use_privsep=yes])
if test x"$ac_cv_use_privsep" = x"yes"; then
	AC_CHECK_LIB(cap, cap_get_proc,, AC_MSG_ERROR(libcap-dev developer headers not found))
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
AC_SUBST(HIPL_I3_CLIENT, "$HIPL/i3/i3_client")
AC_SUBST(HIPL_I3, "$HIPL/i3/i3")
AC_SUBST(HIPL_AESHASH, "$HIPL/i3/aeshash")
AC_SUBST(HIPL_I3_CHORD, "$HIPL/i3/chord")
AC_SUBST(HIPL_I3_UTILS, "$HIPL/i3/utils")
AC_SUBST(HIPL_XMLL, `xml2-config --libs`)
AC_SUBST(HIPL_XMLI, `xml2-config --cflags`)
AC_SUBST(HIPL_I3UTILS_LIB_DYNAMIC, "$HIPL_I3_UTILS/libutils.a")
AC_SUBST(HIPL_PJPROJECT, "$HIPL/pjproject")
AC_SUBST(HIPL_PJPROJECT_LIB, "$HIPL_PJPROJECT/pjlib")
AC_SUBST(HIPL_PJPROJECT_LIB_UTIL, "$HIPL_PJPROJECT/pjlib-util")
AC_SUBST(HIPL_PJPROJECT_NATH, "$HIPL_PJPROJECT/pjnath")
AC_SUBST(HIPL_PJPROJECT_MEDIA, "$HIPL_PJPROJECT/pjmedia")
AC_SUBST(HIPL_PJPROJECT_SIP, "$HIPL_PJPROJECT/pjsip")
AC_SUBST(HIPL_PERFORMANCE, "$HIPL/performance")
AC_SUBST(HIPL_PERFORMANCE_LIB, "HIPL_PERFORMANCE/.libs/performance.a")

# This nasty kludge was created by Miika with:
# find pjproject -type f|egrep -v '(\.arch-ids|.*\.depend|.*\.a|.*\.o|.*\/bin\/)'|xargs echo

AC_SUBST(PJPROJECT_FILES, "pjproject/Makefile pjproject/pjproject.dsw pjproject/build/os-darwinos.mak pjproject/build/os-auto.mak.in pjproject/build/os-rtems.mak pjproject/build/os-auto.mak pjproject/build/rules.mak pjproject/build/m-sparc.mak pjproject/build/m-arm.mak pjproject/build/host-mingw.mak pjproject/build/host-win32.mak pjproject/build/os-linux.mak pjproject/build/cc-gcc.mak pjproject/build/m-alpha.mak pjproject/build/m-mpc860.mak pjproject/build/os-linux-kernel.mak pjproject/build/m-auto.mak pjproject/build/m-x86_64.mak pjproject/build/m-powerpc.mak pjproject/build/host-unix.mak pjproject/build/os-sunos.mak pjproject/build/cc-vc.mak pjproject/build/m-m68k.mak pjproject/build/os-palmos.mak pjproject/build/os-win32.mak pjproject/build/m-i386.mak pjproject/build/common.mak pjproject/config.status pjproject/svn_pset pjproject/pjlib/src/pj/ioqueue_dummy.c pjproject/pjlib/src/pj/pool_buf.c pjproject/pjlib/src/pj/pool_dbg.c pjproject/pjlib/src/pj/pool_caching.c pjproject/pjlib/src/pj/ioqueue_epoll.c pjproject/pjlib/src/pj/os_error_linux_kernel.c pjproject/pjlib/src/pj/guid_simple.c pjproject/pjlib/src/pj/ctype.c pjproject/pjlib/src/pj/log.c pjproject/pjlib/src/pj/os_time_unix.c pjproject/pjlib/src/pj/sock_select_symbian.cpp pjproject/pjlib/src/pj/os_core_unix.c pjproject/pjlib/src/pj/os_core_win32.c pjproject/pjlib/src/pj/ioqueue_common_abs.c pjproject/pjlib/src/pj/ioqueue_common_abs.h pjproject/pjlib/src/pj/unicode_win32.c pjproject/pjlib/src/pj/addr_resolv_sock.c pjproject/pjlib/src/pj/pool_policy_new.cpp pjproject/pjlib/src/pj/timer_symbian.cpp pjproject/pjlib/src/pj/os_timestamp_linux_kernel.c pjproject/pjlib/src/pj/file_access_win32.c pjproject/pjlib/src/pj/ip_helper_generic.c pjproject/pjlib/src/pj/symbols.c pjproject/pjlib/src/pj/fifobuf.c pjproject/pjlib/src/pj/sock_linux_kernel.c pjproject/pjlib/src/pj/sock_common.c pjproject/pjlib/src/pj/errno.c pjproject/pjlib/src/pj/os_error_unix.c pjproject/pjlib/src/pj/os_timestamp_win32.c pjproject/pjlib/src/pj/os_symbian.h pjproject/pjlib/src/pj/pool_signature.h pjproject/pjlib/src/pj/timer.c pjproject/pjlib/src/pj/os_error_win32.c pjproject/pjlib/src/pj/compat/sigjmp.c pjproject/pjlib/src/pj/compat/longjmp_i386.S pjproject/pjlib/src/pj/compat/setjmp_i386.S pjproject/pjlib/src/pj/compat/string_compat.c pjproject/pjlib/src/pj/compat/string.c pjproject/pjlib/src/pj/os_time_linux_kernel.c pjproject/pjlib/src/pj/pool_policy_malloc.c pjproject/pjlib/src/pj/config.c pjproject/pjlib/src/pj/ip_helper_win32.c pjproject/pjlib/src/pj/os_timestamp_posix.c pjproject/pjlib/src/pj/sock_bsd.c pjproject/pjlib/src/pj/file_access_unistd.c pjproject/pjlib/src/pj/os_timestamp_common.c pjproject/pjlib/src/pj/hash.c pjproject/pjlib/src/pj/guid.c pjproject/pjlib/src/pj/log_writer_printk.c pjproject/pjlib/src/pj/log_writer_stdout.c pjproject/pjlib/src/pj/sock_select.c pjproject/pjlib/src/pj/os_error_symbian.cpp pjproject/pjlib/src/pj/list.c pjproject/pjlib/src/pj/pool_policy_kmalloc.c pjproject/pjlib/src/pj/lock.c pjproject/pjlib/src/pj/file_io_win32.c pjproject/pjlib/src/pj/ioqueue_winnt.c pjproject/pjlib/src/pj/pool.c pjproject/pjlib/src/pj/addr_resolv_symbian.cpp pjproject/pjlib/src/pj/rand.c pjproject/pjlib/src/pj/types.c pjproject/pjlib/src/pj/os_core_linux_kernel.c pjproject/pjlib/src/pj/unicode_symbian.cpp pjproject/pjlib/src/pj/ioqueue_select.c pjproject/pjlib/src/pj/rbtree.c pjproject/pjlib/src/pj/sock_symbian.cpp pjproject/pjlib/src/pj/guid_win32.c pjproject/pjlib/src/pj/extra-exports.c pjproject/pjlib/src/pj/array.c pjproject/pjlib/src/pj/os_core_symbian.cpp pjproject/pjlib/src/pj/os_time_win32.c pjproject/pjlib/src/pj/except.c pjproject/pjlib/src/pj/addr_resolv_linux_kernel.c pjproject/pjlib/src/pj/ioqueue_linux_kernel.c pjproject/pjlib/src/pj/exception_symbian.cpp pjproject/pjlib/src/pj/guid_uuid.c pjproject/pjlib/src/pj/log_writer_symbian_console.cpp pjproject/pjlib/src/pj/string.c pjproject/pjlib/src/pj/ioqueue_symbian.cpp pjproject/pjlib/src/pj/os_rwmutex.c pjproject/pjlib/src/pj/file_io_ansi.c pjproject/pjlib/src/pj/os_time_common.c pjproject/pjlib/src/pj/os_time_bsd.c pjproject/pjlib/src/pjlib++-test/main.cpp pjproject/pjlib/src/pjlib-samples/log.c pjproject/pjlib/src/pjlib-samples/list.c pjproject/pjlib/src/pjlib-samples/except.c pjproject/pjlib/src/pjlib-test/main_mod.c pjproject/pjlib/src/pjlib-test/timestamp.c pjproject/pjlib/src/pjlib-test/os.c pjproject/pjlib/src/pjlib-test/atomic.c pjproject/pjlib/src/pjlib-test/udp_echo_srv_ioqueue.c pjproject/pjlib/src/pjlib-test/fifobuf.c pjproject/pjlib/src/pjlib-test/sleep.c pjproject/pjlib/src/pjlib-test/errno.c pjproject/pjlib/src/pjlib-test/timer.c pjproject/pjlib/src/pjlib-test/ioq_unreg.c pjproject/pjlib/src/pjlib-test/file.c pjproject/pjlib/src/pjlib-test/main_win32.c pjproject/pjlib/src/pjlib-test/list.c pjproject/pjlib/src/pjlib-test/main.c pjproject/pjlib/src/pjlib-test/mutex.c pjproject/pjlib/src/pjlib-test/rtems_network_config.h pjproject/pjlib/src/pjlib-test/pool.c pjproject/pjlib/src/pjlib-test/rand.c pjproject/pjlib/src/pjlib-test/select.c pjproject/pjlib/src/pjlib-test/sock.c pjproject/pjlib/src/pjlib-test/test.c pjproject/pjlib/src/pjlib-test/test.h pjproject/pjlib/src/pjlib-test/echo_clt.c pjproject/pjlib/src/pjlib-test/sock_perf.c pjproject/pjlib/src/pjlib-test/util.c pjproject/pjlib/src/pjlib-test/rbtree.c pjproject/pjlib/src/pjlib-test/thread.c pjproject/pjlib/src/pjlib-test/exception.c pjproject/pjlib/src/pjlib-test/main_symbian.cpp pjproject/pjlib/src/pjlib-test/udp_echo_srv_sync.c pjproject/pjlib/src/pjlib-test/ioq_perf.c pjproject/pjlib/src/pjlib-test/pool_perf.c pjproject/pjlib/src/pjlib-test/string.c pjproject/pjlib/src/pjlib-test/main_rtems.c pjproject/pjlib/src/pjlib-test/ioq_tcp.c pjproject/pjlib/src/pjlib-test/ioq_udp.c pjproject/pjlib/docs/doxygen.cfg pjproject/pjlib/docs/doxygen.css pjproject/pjlib/docs/footer.html pjproject/pjlib/docs/header.html pjproject/pjlib/build/os-darwinos.mak pjproject/pjlib/build/Makefile pjproject/pjlib/build/os-auto.mak.in pjproject/pjlib/build/os-rtems.mak pjproject/pjlib/build/os-auto.mak pjproject/pjlib/build/pjlib++-test.dsp pjproject/pjlib/build/pjlib.vcproj pjproject/pjlib/build/pjlib_test.vcproj pjproject/pjlib/build/os-linux.mak pjproject/pjlib/build/pjlib.dsp pjproject/pjlib/build/pjlib.dsw pjproject/pjlib/build/wince-evc4/pjlib_test_wince.vcp pjproject/pjlib/build/wince-evc4/pjlib_wince.vcp pjproject/pjlib/build/wince-evc4/pjlib_wince.vcw pjproject/pjlib/build/os-linux-kernel.mak pjproject/pjlib/build/pjlib_samples.dsp pjproject/pjlib/build/pjlib_samples.mak pjproject/pjlib/build/pjlib++.dsp pjproject/pjlib/build/pjlib_test.dsp pjproject/pjlib/build/os-sunos.mak pjproject/pjlib/build/os-win32.mak pjproject/pjlib/include/pj/os.h pjproject/pjlib/include/pj/file_io.h pjproject/pjlib/include/pj/list_i.h pjproject/pjlib/include/pj/pool_alt.h pjproject/pjlib/include/pj/pool_buf.h pjproject/pjlib/include/pj/ctype.h pjproject/pjlib/include/pj/log.h pjproject/pjlib/include/pj/unicode.h pjproject/pjlib/include/pj/ioqueue.h pjproject/pjlib/include/pj/config_site.h pjproject/pjlib/include/pj/fifobuf.h pjproject/pjlib/include/pj/pool_i.h pjproject/pjlib/include/pj/errno.h pjproject/pjlib/include/pj/string_i.h pjproject/pjlib/include/pj/timer.h pjproject/pjlib/include/pj/compat/stdfileio.h pjproject/pjlib/include/pj/compat/m_m68k.h pjproject/pjlib/include/pj/compat/os_linux_kernel.h pjproject/pjlib/include/pj/compat/m_sparc.h pjproject/pjlib/include/pj/compat/ctype.h pjproject/pjlib/include/pj/compat/cc_codew.h pjproject/pjlib/include/pj/compat/os_win32.h pjproject/pjlib/include/pj/compat/os_darwinos.h pjproject/pjlib/include/pj/compat/m_auto.h.in pjproject/pjlib/include/pj/compat/os_auto.h pjproject/pjlib/include/pj/compat/errno.h pjproject/pjlib/include/pj/compat/malloc.h pjproject/pjlib/include/pj/compat/m_x86_64.h pjproject/pjlib/include/pj/compat/size_t.h pjproject/pjlib/include/pj/compat/os_symbian.h pjproject/pjlib/include/pj/compat/m_alpha.h pjproject/pjlib/include/pj/compat/m_armv4.h pjproject/pjlib/include/pj/compat/cc_gcc.h pjproject/pjlib/include/pj/compat/m_powerpc.h pjproject/pjlib/include/pj/compat/os_linux.h pjproject/pjlib/include/pj/compat/os_rtems.h pjproject/pjlib/include/pj/compat/os_win32_wince.h pjproject/pjlib/include/pj/compat/rand.h pjproject/pjlib/include/pj/compat/high_precision.h pjproject/pjlib/include/pj/compat/time.h pjproject/pjlib/include/pj/compat/stdarg.h pjproject/pjlib/include/pj/compat/setjmp.h pjproject/pjlib/include/pj/compat/os_sunos.h pjproject/pjlib/include/pj/compat/os_auto.h.in pjproject/pjlib/include/pj/compat/cc_gcce.h pjproject/pjlib/include/pj/compat/string.h pjproject/pjlib/include/pj/compat/os_palmos.h pjproject/pjlib/include/pj/compat/assert.h pjproject/pjlib/include/pj/compat/cc_armcc.h pjproject/pjlib/include/pj/compat/m_auto.h pjproject/pjlib/include/pj/compat/cc_msvc.h pjproject/pjlib/include/pj/compat/cc_mwcc.h pjproject/pjlib/include/pj/compat/m_i386.h pjproject/pjlib/include/pj/compat/socket.h pjproject/pjlib/include/pj/ip_helper.h pjproject/pjlib/include/pj/config.h pjproject/pjlib/include/pj/doxygen.h pjproject/pjlib/include/pj/hash.h pjproject/pjlib/include/pj/guid.h pjproject/pjlib/include/pj/sock_select.h pjproject/pjlib/include/pj/list.h pjproject/pjlib/include/pj/lock.h pjproject/pjlib/include/pj/config_site_sample.h pjproject/pjlib/include/pj/file_access.h pjproject/pjlib/include/pj/pool.h pjproject/pjlib/include/pj/rand.h pjproject/pjlib/include/pj/types.h pjproject/pjlib/include/pj/sock.h pjproject/pjlib/include/pj/rbtree.h pjproject/pjlib/include/pj/array.h pjproject/pjlib/include/pj/except.h pjproject/pjlib/include/pj/string.h pjproject/pjlib/include/pj/assert.h pjproject/pjlib/include/pj/addr_resolv.h pjproject/pjlib/include/pj++/tree.hpp pjproject/pjlib/include/pj++/list.hpp pjproject/pjlib/include/pj++/timer.hpp pjproject/pjlib/include/pj++/types.hpp pjproject/pjlib/include/pj++/pool.hpp pjproject/pjlib/include/pj++/file.hpp pjproject/pjlib/include/pj++/string.hpp pjproject/pjlib/include/pj++/scanner.hpp pjproject/pjlib/include/pj++/hash.hpp pjproject/pjlib/include/pj++/os.hpp pjproject/pjlib/include/pj++/lock.hpp pjproject/pjlib/include/pj++/proactor.hpp pjproject/pjlib/include/pj++/sock.hpp pjproject/pjlib/include/pjlib++.hpp pjproject/pjlib/include/pjlib.h pjproject/pjsip/src/pjsip/sip_parser.c pjproject/pjsip/src/pjsip/sip_msg.c pjproject/pjsip/src/pjsip/sip_uri.c pjproject/pjsip/src/pjsip/sip_auth_parser.c pjproject/pjsip/src/pjsip/sip_util_proxy.c pjproject/pjsip/src/pjsip/sip_errno.c pjproject/pjsip/src/pjsip/sip_ua_layer.c pjproject/pjsip/src/pjsip/sip_transport.c pjproject/pjsip/src/pjsip/sip_util_statefull.c pjproject/pjsip/src/pjsip/sip_transport_loop.c pjproject/pjsip/src/pjsip/sip_auth_server.c pjproject/pjsip/src/pjsip/sip_transport_tcp.c pjproject/pjsip/src/pjsip/sip_transport_udp.c pjproject/pjsip/src/pjsip/sip_endpoint.c pjproject/pjsip/src/pjsip/sip_util.c pjproject/pjsip/src/pjsip/sip_dialog.c pjproject/pjsip/src/pjsip/sip_auth_client.c pjproject/pjsip/src/pjsip/sip_tel_uri.c pjproject/pjsip/src/pjsip/sip_transaction.c pjproject/pjsip/src/pjsip/sip_transport_tls_ossl.c pjproject/pjsip/src/pjsip/sip_auth_aka.c pjproject/pjsip/src/pjsip/sip_auth_msg.c pjproject/pjsip/src/pjsip/sip_resolve.c pjproject/pjsip/src/pjsip-simple/presence.c pjproject/pjsip/src/pjsip-simple/xpidf.c pjproject/pjsip/src/pjsip-simple/errno.c pjproject/pjsip/src/pjsip-simple/evsub.c pjproject/pjsip/src/pjsip-simple/presence_body.c pjproject/pjsip/src/pjsip-simple/pidf.c pjproject/pjsip/src/pjsip-simple/rpid.c pjproject/pjsip/src/pjsip-simple/evsub_msg.c pjproject/pjsip/src/pjsip-simple/iscomposing.c pjproject/pjsip/src/pjsip-simple/publishc.c pjproject/pjsip/src/test-pjsip/txdata_test.c pjproject/pjsip/src/test-pjsip/transport_tcp_test.c pjproject/pjsip/src/test-pjsip/msg_logger.c pjproject/pjsip/src/test-pjsip/tsx_uac_test.c pjproject/pjsip/src/test-pjsip/msg_test.c pjproject/pjsip/src/test-pjsip/dns_test.c pjproject/pjsip/src/test-pjsip/transport_loop_test.c pjproject/pjsip/src/test-pjsip/dlg_core_test.c pjproject/pjsip/src/test-pjsip/main.c pjproject/pjsip/src/test-pjsip/tsx_bench.c pjproject/pjsip/src/test-pjsip/msg_err_test.c pjproject/pjsip/src/test-pjsip/tsx_basic_test.c pjproject/pjsip/src/test-pjsip/test.c pjproject/pjsip/src/test-pjsip/test.h pjproject/pjsip/src/test-pjsip/inv_offer_answer_test.c pjproject/pjsip/src/test-pjsip/transport_udp_test.c pjproject/pjsip/src/test-pjsip/tsx_uas_test.c pjproject/pjsip/src/test-pjsip/uri_test.c pjproject/pjsip/src/test-pjsip/main_rtems.c pjproject/pjsip/src/test-pjsip/transport_test.c pjproject/pjsip/src/pjsua-lib/pjsua_im.c pjproject/pjsip/src/pjsua-lib/pjsua_call.c pjproject/pjsip/src/pjsua-lib/pjsua_core.c pjproject/pjsip/src/pjsua-lib/pjsua_pres.c pjproject/pjsip/src/pjsua-lib/pjsua_acc.c pjproject/pjsip/src/pjsua-lib/pjsua_media.c pjproject/pjsip/src/pjsip-ua/sip_inv.c pjproject/pjsip/src/pjsip-ua/sip_reg.c pjproject/pjsip/src/pjsip-ua/sip_replaces.c pjproject/pjsip/src/pjsip-ua/sip_xfer.c pjproject/pjsip/src/pjsip-ua/sip_100rel.c pjproject/pjsip/docs/siprtp.jpg pjproject/pjsip/docs/doxygen.cfg pjproject/pjsip/docs/pjsip-perf.jpg pjproject/pjsip/docs/footer.html pjproject/pjsip/docs/doxygen.h pjproject/pjsip/docs/PJSUA-TESTING.txt pjproject/pjsip/docs/pjsua.jpg pjproject/pjsip/docs/TRANSPORT-PROBLEMS.TXT pjproject/pjsip/docs/header.html pjproject/pjsip/docs/pjsip-arch.jpg pjproject/pjsip/build/pjsua_lib.vcproj pjproject/pjsip/build/test_pjsip.vcproj pjproject/pjsip/build/Makefile pjproject/pjsip/build/pjsip_simple.vcproj pjproject/pjsip/build/os-auto.mak.in pjproject/pjsip/build/pjsip_core.vcproj pjproject/pjsip/build/pjsip_simple.dsp pjproject/pjsip/build/os-rtems.mak pjproject/pjsip/build/os-auto.mak pjproject/pjsip/build/test_pjsip.dsp pjproject/pjsip/build/pjsip.dsw pjproject/pjsip/build/wince-evc4/pjsua_lib_wince.vcp pjproject/pjsip/build/wince-evc4/pjsip_core_wince.vcp pjproject/pjsip/build/wince-evc4/pjsip_simple_wince.vcp pjproject/pjsip/build/wince-evc4/pjsip_ua_wince.vcp pjproject/pjsip/build/wince-evc4/pjsip_wince.vcw pjproject/pjsip/build/pjsua_lib.dsp pjproject/pjsip/build/pjsip_core.dsp pjproject/pjsip/build/pjsip_ua.dsp pjproject/pjsip/build/pjsip_ua.vcproj pjproject/pjsip/include/pjsip/sip_parser.h pjproject/pjsip/include/pjsip/sip_msg.h pjproject/pjsip/include/pjsip/sip_uri.h pjproject/pjsip/include/pjsip/sip_auth_parser.h pjproject/pjsip/include/pjsip/print_util.h pjproject/pjsip/include/pjsip/sip_config.h pjproject/pjsip/include/pjsip/sip_autoconf.h.in pjproject/pjsip/include/pjsip/sip_private.h pjproject/pjsip/include/pjsip/sip_auth.h pjproject/pjsip/include/pjsip/sip_errno.h pjproject/pjsip/include/pjsip/sip_ua_layer.h pjproject/pjsip/include/pjsip/sip_transport.h pjproject/pjsip/include/pjsip/sip_event.h pjproject/pjsip/include/pjsip/sip_transport_loop.h pjproject/pjsip/include/pjsip/sip_transport_tcp.h pjproject/pjsip/include/pjsip/sip_transport_tls.h pjproject/pjsip/include/pjsip/sip_transport_udp.h pjproject/pjsip/include/pjsip/sip_endpoint.h pjproject/pjsip/include/pjsip/sip_util.h pjproject/pjsip/include/pjsip/sip_types.h pjproject/pjsip/include/pjsip/sip_dialog.h pjproject/pjsip/include/pjsip/sip_tel_uri.h pjproject/pjsip/include/pjsip/sip_transaction.h pjproject/pjsip/include/pjsip/sip_auth_aka.h pjproject/pjsip/include/pjsip/sip_auth_msg.h pjproject/pjsip/include/pjsip/sip_resolve.h pjproject/pjsip/include/pjsip/sip_autoconf.h pjproject/pjsip/include/pjsip/sip_module.h pjproject/pjsip/include/pjsip_simple.h pjproject/pjsip/include/pjsip-simple/presence.h pjproject/pjsip/include/pjsip-simple/xpidf.h pjproject/pjsip/include/pjsip-simple/errno.h pjproject/pjsip/include/pjsip-simple/evsub.h pjproject/pjsip/include/pjsip-simple/pidf.h pjproject/pjsip/include/pjsip-simple/types.h pjproject/pjsip/include/pjsip-simple/rpid.h pjproject/pjsip/include/pjsip-simple/publish.h pjproject/pjsip/include/pjsip-simple/evsub_msg.h pjproject/pjsip/include/pjsip-simple/iscomposing.h pjproject/pjsip/include/pjsip_auth.h pjproject/pjsip/include/pjsip_ua.h pjproject/pjsip/include/pjsua-lib/pjsua.h pjproject/pjsip/include/pjsua-lib/pjsua_internal.h pjproject/pjsip/include/pjsip-ua/sip_inv.h pjproject/pjsip/include/pjsip-ua/sip_replaces.h pjproject/pjsip/include/pjsip-ua/sip_regc.h pjproject/pjsip/include/pjsip-ua/sip_xfer.h pjproject/pjsip/include/pjsip-ua/sip_100rel.h pjproject/pjsip/include/pjsip.h pjproject/configure-legacy pjproject/user.mak.sample pjproject/configure pjproject/build.mak.in pjproject/c++-build.mak pjproject/config.guess pjproject/install-sh pjproject/config.log pjproject/config.sub pjproject/pjsip-apps/src/symbian_ua/ua.h pjproject/pjsip-apps/src/symbian_ua/ua.cpp pjproject/pjsip-apps/src/symbian_ua/main_symbian.cpp pjproject/pjsip-apps/src/pjsua/pjsua_app.c pjproject/pjsip-apps/src/pjsua/main.c pjproject/pjsip-apps/src/pjsua/main_rtems.c pjproject/pjsip-apps/src/samples/playfile.c pjproject/pjsip-apps/src/samples/debug.c pjproject/pjsip-apps/src/samples/footprint.c pjproject/pjsip-apps/src/samples/siprtp_report.c pjproject/pjsip-apps/src/samples/playsine.c pjproject/pjsip-apps/src/samples/level.c pjproject/pjsip-apps/src/samples/recfile.c pjproject/pjsip-apps/src/samples/siprtp.c pjproject/pjsip-apps/src/samples/pjsip-perf.c pjproject/pjsip-apps/src/samples/sndinfo.c pjproject/pjsip-apps/src/samples/confsample.c pjproject/pjsip-apps/src/samples/sipstateless.c pjproject/pjsip-apps/src/samples/stateful_proxy.c pjproject/pjsip-apps/src/samples/simple_pjsua.c pjproject/pjsip-apps/src/samples/invtester.c pjproject/pjsip-apps/src/samples/sndtest.c pjproject/pjsip-apps/src/samples/stateless_proxy.c pjproject/pjsip-apps/src/samples/confbench.c pjproject/pjsip-apps/src/samples/aectest.c pjproject/pjsip-apps/src/samples/util.h pjproject/pjsip-apps/src/samples/streamutil.c pjproject/pjsip-apps/src/samples/resampleplay.c pjproject/pjsip-apps/src/samples/main_rtems.c pjproject/pjsip-apps/src/samples/tonegen.c pjproject/pjsip-apps/src/samples/simpleua.c pjproject/pjsip-apps/src/samples/proxy.h pjproject/pjsip-apps/src/pjsua_wince/resource.h pjproject/pjsip-apps/src/pjsua_wince/pjsua_wince.h pjproject/pjsip-apps/src/pjsua_wince/StdAfx.h pjproject/pjsip-apps/src/pjsua_wince/pjsua_wince.rc pjproject/pjsip-apps/src/pjsua_wince/README.TXT pjproject/pjsip-apps/src/pjsua_wince/pjsua_wince.cpp pjproject/pjsip-apps/src/pjsua_wince/pjsua_wince.ico pjproject/pjsip-apps/src/pjsua_wince/pjsua_wince.vcp pjproject/pjsip-apps/src/pjsua_wince/newres.h pjproject/pjsip-apps/src/pjsua_wince/StdAfx.cpp pjproject/pjsip-apps/src/py_pjsua/Makefile pjproject/pjsip-apps/src/py_pjsua/helper.mak pjproject/pjsip-apps/src/py_pjsua/pjsua_app.py pjproject/pjsip-apps/src/py_pjsua/pjsua.py pjproject/pjsip-apps/src/py_pjsua/py_pjsua.def pjproject/pjsip-apps/src/py_pjsua/setup.py pjproject/pjsip-apps/src/py_pjsua/py_pjsua.c pjproject/pjsip-apps/src/py_pjsua/py_pjsua.h pjproject/pjsip-apps/src/symsndtest/app_main.cpp pjproject/pjsip-apps/src/symsndtest/main_symbian.cpp pjproject/pjsip-apps/build/py_pjsua.vcproj pjproject/pjsip-apps/build/Makefile pjproject/pjsip-apps/build/sample_debug.dsp pjproject/pjsip-apps/build/sample_debug.vcproj pjproject/pjsip-apps/build/samples.vcproj pjproject/pjsip-apps/build/pjsua.vcproj pjproject/pjsip-apps/build/Samples.mak pjproject/pjsip-apps/build/wince-evc4/wince_demos.vcw pjproject/pjsip-apps/build/pjsip_apps.dsw pjproject/pjsip-apps/build/pjsua.dsp pjproject/pjsip-apps/build/Samples-vc.mak pjproject/pjsip-apps/build/Footprint.mak pjproject/pjsip-apps/build/samples.dsp pjproject/pjsip-apps/build/py_pjsua.dsp pjproject/pjsip-apps/build/os-win32.mak pjproject/pjsip-apps/build/get-footprint.py pjproject/libpj.pc.in pjproject/svn_add pjproject/README-RTEMS pjproject/README.txt pjproject/pjnath/src/pjstun-srv-test/turn_usage.c pjproject/pjnath/src/pjstun-srv-test/bind_usage.c pjproject/pjnath/src/pjstun-srv-test/main.c pjproject/pjnath/src/pjstun-srv-test/usage.c pjproject/pjnath/src/pjstun-srv-test/server.c pjproject/pjnath/src/pjstun-srv-test/server.h pjproject/pjnath/src/pjnath-test/main.c pjproject/pjnath/src/pjnath-test/test.c pjproject/pjnath/src/pjnath-test/test.h pjproject/pjnath/src/pjnath-test/stun.c pjproject/pjnath/src/pjnath-test/ice_test.c pjproject/pjnath/src/pjstun-client/client_main.c pjproject/pjnath/src/pjnath/stun_session.c pjproject/pjnath/src/pjnath/stun_msg_dump.c pjproject/pjnath/src/pjnath/errno.c pjproject/pjnath/src/pjnath/nat_detect.c pjproject/pjnath/src/pjnath/ice_session.c pjproject/pjnath/src/pjnath/stun_msg.c pjproject/pjnath/src/pjnath/ice_strans.c pjproject/pjnath/src/pjnath/stun_transaction.c pjproject/pjnath/src/pjnath/stun_auth.c pjproject/pjnath/docs/doxygen.cfg pjproject/pjnath/docs/doxygen.css pjproject/pjnath/docs/footer.html pjproject/pjnath/docs/stun-arch.jpg pjproject/pjnath/docs/ice-arch.jpg pjproject/pjnath/docs/header.html pjproject/pjnath/build/Makefile pjproject/pjnath/build/pjnath.dsp pjproject/pjnath/build/pjnath.dsw pjproject/pjnath/build/pjstun_srv_test.vcproj pjproject/pjnath/build/pjstun_client.vcproj pjproject/pjnath/build/pjnath.vcproj pjproject/pjnath/build/pjnath_test.vcproj pjproject/pjnath/build/pjstun_client.dsp pjproject/pjnath/build/wince-evc4/pjnath_wince.vcp pjproject/pjnath/build/pjnath_test.dsp pjproject/pjnath/build/pjstun_srv_test.dsp pjproject/pjnath/include/pjnath.h pjproject/pjnath/include/pjnath/stun_session.h pjproject/pjnath/include/pjnath/stun_config.h pjproject/pjnath/include/pjnath/errno.h pjproject/pjnath/include/pjnath/nat_detect.h pjproject/pjnath/include/pjnath/ice_session.h pjproject/pjnath/include/pjnath/config.h pjproject/pjnath/include/pjnath/types.h pjproject/pjnath/include/pjnath/stun_msg.h pjproject/pjnath/include/pjnath/ice_strans.h pjproject/pjnath/include/pjnath/stun_transaction.h pjproject/pjnath/include/pjnath/stun_auth.h pjproject/build.mak pjproject/build.symbian/pjlibU.def pjproject/build.symbian/pjproject.cww pjproject/build.symbian/pjsip_simple.mmp pjproject/build.symbian/pjlib_util.mmp pjproject/build.symbian/pjsip_uaU.def pjproject/build.symbian/pjnath.mmp pjproject/build.symbian/pjsdp.mmp pjproject/build.symbian/pjlib.mmp pjproject/build.symbian/pjnathU.def pjproject/build.symbian/pjsipU.def pjproject/build.symbian/pjstun_client.mmp pjproject/build.symbian/pjsip.mmp pjproject/build.symbian/pjsua_lib.mmp pjproject/build.symbian/symbian_audio.mmp pjproject/build.symbian/pjlib_test.mmp pjproject/build.symbian/pjsip_ua.mmp pjproject/build.symbian/00.bat pjproject/build.symbian/01.bat pjproject/build.symbian/pjmediaU.def pjproject/build.symbian/symsndtest.mmp pjproject/build.symbian/pjsdpU.def pjproject/build.symbian/pjsua_libU.def pjproject/build.symbian/pjsip_simpleU.def pjproject/build.symbian/symbian_ua.mmp pjproject/build.symbian/bld.inf pjproject/build.symbian/pjlib_utilU.def pjproject/build.symbian/symbian_audioU.def pjproject/build.symbian/null_audio.mmp pjproject/build.symbian/makedef.sh pjproject/build.symbian/pjmedia.mmp pjproject/build.symbian/null_audioU.def pjproject/self-test.mak pjproject/aconfigure pjproject/pjproject-vs8.sln pjproject/pjmedia/src/test/sdptest.c pjproject/pjmedia/src/test/jbuf_test.c pjproject/pjmedia/src/test/session_test.c pjproject/pjmedia/src/test/main.c pjproject/pjmedia/src/test/rtp_test.c pjproject/pjmedia/src/test/test.c pjproject/pjmedia/src/test/test.h pjproject/pjmedia/src/test/sdp_neg_test.c pjproject/pjmedia/src/test/audio_tool.c pjproject/pjmedia/src/pjmedia-codec/speex_codec.c pjproject/pjmedia/src/pjmedia-codec/l16.c pjproject/pjmedia/src/pjmedia-codec/gsm.c pjproject/pjmedia/src/pjmedia-codec/ilbc.c pjproject/pjmedia/src/pjmedia/alaw_ulaw.c pjproject/pjmedia/src/pjmedia/codec.c pjproject/pjmedia/src/pjmedia/sdp_cmp.c pjproject/pjmedia/src/pjmedia/sdp_neg.c pjproject/pjmedia/src/pjmedia/resample_port.c pjproject/pjmedia/src/pjmedia/bidirectional.c pjproject/pjmedia/src/pjmedia/sdp.c pjproject/pjmedia/src/pjmedia/rtp.c pjproject/pjmedia/src/pjmedia/alaw_ulaw_table.c pjproject/pjmedia/src/pjmedia/pasound.c pjproject/pjmedia/src/pjmedia/clock_thread.c pjproject/pjmedia/src/pjmedia/silencedet.c pjproject/pjmedia/src/pjmedia/resample_speex.c pjproject/pjmedia/src/pjmedia/echo_common.c pjproject/pjmedia/src/pjmedia/conference.c pjproject/pjmedia/src/pjmedia/wav_playlist.c pjproject/pjmedia/src/pjmedia/session.c pjproject/pjmedia/src/pjmedia/nullsound.c pjproject/pjmedia/src/pjmedia/errno.c pjproject/pjmedia/src/pjmedia/g711.c pjproject/pjmedia/src/pjmedia/null_port.c pjproject/pjmedia/src/pjmedia/wav_player.c pjproject/pjmedia/src/pjmedia/mem_player.c pjproject/pjmedia/src/pjmedia/jbuf.c pjproject/pjmedia/src/pjmedia/mem_capture.c pjproject/pjmedia/src/pjmedia/wav_writer.c pjproject/pjmedia/src/pjmedia/transport_ice.c pjproject/pjmedia/src/pjmedia/port.c pjproject/pjmedia/src/pjmedia/transport_udp.c pjproject/pjmedia/src/pjmedia/master_port.c pjproject/pjmedia/src/pjmedia/echo_suppress.c pjproject/pjmedia/src/pjmedia/rtcp.c pjproject/pjmedia/src/pjmedia/plc_common.c pjproject/pjmedia/src/pjmedia/dsound.c pjproject/pjmedia/src/pjmedia/symbian_sound.cpp pjproject/pjmedia/src/pjmedia/wave.c pjproject/pjmedia/src/pjmedia/sound_port.c pjproject/pjmedia/src/pjmedia/echo_port.c pjproject/pjmedia/src/pjmedia/echo_internal.h pjproject/pjmedia/src/pjmedia/splitcomb.c pjproject/pjmedia/src/pjmedia/echo_speex.c pjproject/pjmedia/src/pjmedia/stream.c pjproject/pjmedia/src/pjmedia/endpoint.c pjproject/pjmedia/src/pjmedia/resample_resample.c pjproject/pjmedia/src/pjmedia/tonegen.c pjproject/pjmedia/src/pjmedia/resample_libsamplerate.c pjproject/pjmedia/docs/media-flow.jpg pjproject/pjmedia/docs/media-flow.vsd pjproject/pjmedia/docs/siprtp.jpg pjproject/pjmedia/docs/doxygen.cfg pjproject/pjmedia/docs/footer.html pjproject/pjmedia/docs/sndtest.jpg pjproject/pjmedia/docs/master-port.jpg pjproject/pjmedia/docs/header.html pjproject/pjmedia/docs/sample-manual-resampling.jpg pjproject/pjmedia/build/os-darwinos.mak pjproject/pjmedia/build/pjaut.dsp pjproject/pjmedia/build/Makefile pjproject/pjmedia/build/os-auto.mak.in pjproject/pjmedia/build/os-rtems.mak pjproject/pjmedia/build/os-auto.mak pjproject/pjmedia/build/Jbtest.dat pjproject/pjmedia/build/os-linux.mak pjproject/pjmedia/build/wince-evc4/pjmedia_codec_wince.vcp pjproject/pjmedia/build/wince-evc4/pjmedia_wince.vcp pjproject/pjmedia/build/wince-evc4/pjmedia_wince.vcw pjproject/pjmedia/build/pjmedia_codec.dsp pjproject/pjmedia/build/pjmedia.vcproj pjproject/pjmedia/build/m-x86_64.mak pjproject/pjmedia/build/pjmedia_test.dsp pjproject/pjmedia/build/os-win32.mak pjproject/pjmedia/build/m-i386.mak pjproject/pjmedia/build/pjmedia.dsp pjproject/pjmedia/build/pjmedia.dsw pjproject/pjmedia/build/pjmedia_codec.vcproj pjproject/pjmedia/README.txt pjproject/pjmedia/include/pjmedia-codec.h pjproject/pjmedia/include/pjmedia.h pjproject/pjmedia/include/pjmedia-codec/config_auto.h pjproject/pjmedia/include/pjmedia-codec/l16.h pjproject/pjmedia/include/pjmedia-codec/gsm.h pjproject/pjmedia/include/pjmedia-codec/speex.h pjproject/pjmedia/include/pjmedia-codec/config.h pjproject/pjmedia/include/pjmedia-codec/ilbc.h pjproject/pjmedia/include/pjmedia-codec/types.h pjproject/pjmedia/include/pjmedia-codec/config_auto.h.in pjproject/pjmedia/include/pjmedia/clock.h pjproject/pjmedia/include/pjmedia/alaw_ulaw.h pjproject/pjmedia/include/pjmedia/codec.h pjproject/pjmedia/include/pjmedia/config_auto.h pjproject/pjmedia/include/pjmedia/sdp_neg.h pjproject/pjmedia/include/pjmedia/bidirectional.h pjproject/pjmedia/include/pjmedia/plc.h pjproject/pjmedia/include/pjmedia/sdp.h pjproject/pjmedia/include/pjmedia/rtp.h pjproject/pjmedia/include/pjmedia/silencedet.h pjproject/pjmedia/include/pjmedia/conference.h pjproject/pjmedia/include/pjmedia/wav_playlist.h pjproject/pjmedia/include/pjmedia/session.h pjproject/pjmedia/include/pjmedia/errno.h pjproject/pjmedia/include/pjmedia/sound.h pjproject/pjmedia/include/pjmedia/g711.h pjproject/pjmedia/include/pjmedia/null_port.h pjproject/pjmedia/include/pjmedia/echo.h pjproject/pjmedia/include/pjmedia/config.h pjproject/pjmedia/include/pjmedia/wav_port.h pjproject/pjmedia/include/pjmedia/doxygen.h pjproject/pjmedia/include/pjmedia/jbuf.h pjproject/pjmedia/include/pjmedia/transport_ice.h pjproject/pjmedia/include/pjmedia/port.h pjproject/pjmedia/include/pjmedia/transport_udp.h pjproject/pjmedia/include/pjmedia/master_port.h pjproject/pjmedia/include/pjmedia/types.h pjproject/pjmedia/include/pjmedia/rtcp.h pjproject/pjmedia/include/pjmedia/wave.h pjproject/pjmedia/include/pjmedia/mem_port.h pjproject/pjmedia/include/pjmedia/sound_port.h pjproject/pjmedia/include/pjmedia/echo_port.h pjproject/pjmedia/include/pjmedia/config_auto.h.in pjproject/pjmedia/include/pjmedia/transport.h pjproject/pjmedia/include/pjmedia/splitcomb.h pjproject/pjmedia/include/pjmedia/stream.h pjproject/pjmedia/include/pjmedia/endpoint.h pjproject/pjmedia/include/pjmedia/tonegen.h pjproject/pjmedia/include/pjmedia/resample.h pjproject/INSTALL.txt pjproject/third_party/gsm/inc/private.h pjproject/third_party/gsm/inc/gsm.h pjproject/third_party/gsm/inc/unproto.h pjproject/third_party/gsm/inc/config.h pjproject/third_party/gsm/inc/toast.h pjproject/third_party/gsm/inc/proto.h pjproject/third_party/gsm/man/bitter.1 pjproject/third_party/gsm/man/gsm_option.3 pjproject/third_party/gsm/man/gsm.3 pjproject/third_party/gsm/man/toast.1 pjproject/third_party/gsm/man/gsm_explode.3 pjproject/third_party/gsm/man/gsm_print.3 pjproject/third_party/gsm/src/toast_lin.c pjproject/third_party/gsm/src/debug.c pjproject/third_party/gsm/src/short_term.c pjproject/third_party/gsm/src/gsm_create.c pjproject/third_party/gsm/src/add.c pjproject/third_party/gsm/src/gsm_option.c pjproject/third_party/gsm/src/lpc.c pjproject/third_party/gsm/src/rpe.c pjproject/third_party/gsm/src/toast_alaw.c pjproject/third_party/gsm/src/preprocess.c pjproject/third_party/gsm/src/table.c pjproject/third_party/gsm/src/toast_ulaw.c pjproject/third_party/gsm/src/code.c pjproject/third_party/gsm/src/decode.c pjproject/third_party/gsm/src/toast.c pjproject/third_party/gsm/src/gsm_destroy.c pjproject/third_party/gsm/src/gsm_implode.c pjproject/third_party/gsm/src/long_term.c pjproject/third_party/gsm/src/gsm_encode.c pjproject/third_party/gsm/src/gsm_decode.c pjproject/third_party/gsm/src/toast_audio.c pjproject/third_party/gsm/src/gsm_explode.c pjproject/third_party/gsm/src/gsm_print.c pjproject/third_party/gsm/tls/bitter.c pjproject/third_party/gsm/tls/taste.c pjproject/third_party/gsm/tls/taste.h pjproject/third_party/gsm/tls/bitter.dta pjproject/third_party/gsm/tls/sweet.c pjproject/third_party/gsm/tls/sour1.dta pjproject/third_party/gsm/tls/sour2.dta pjproject/third_party/gsm/tls/sour.c pjproject/third_party/gsm/tls/ginger.c pjproject/third_party/gsm/tst/run pjproject/third_party/gsm/tst/lin2cod.c pjproject/third_party/gsm/tst/lin2txt.c pjproject/third_party/gsm/tst/cod2lin.c pjproject/third_party/gsm/tst/cod2txt.c pjproject/third_party/gsm/tst/gsm2cod.c pjproject/third_party/gsm/Makefile pjproject/third_party/gsm/README pjproject/third_party/gsm/add-test/add_test.dta pjproject/third_party/gsm/add-test/add_test.c pjproject/third_party/gsm/INSTALL pjproject/third_party/gsm/MACHINES pjproject/third_party/gsm/ChangeLog pjproject/third_party/gsm/COPYRIGHT pjproject/third_party/gsm/MANIFEST pjproject/third_party/mp3/BladeMP3EncDLL.h pjproject/third_party/mp3/mp3_port.h pjproject/third_party/mp3/mp3_writer.c pjproject/third_party/ilbc/iLBC_define.h pjproject/third_party/ilbc/constants.c pjproject/third_party/ilbc/constants.h pjproject/third_party/ilbc/enhancer.c pjproject/third_party/ilbc/enhancer.h pjproject/third_party/ilbc/lsf.c pjproject/third_party/ilbc/lsf.h pjproject/third_party/ilbc/iCBConstruct.c pjproject/third_party/ilbc/iCBConstruct.h pjproject/third_party/ilbc/createCB.c pjproject/third_party/ilbc/createCB.h pjproject/third_party/ilbc/anaFilter.c pjproject/third_party/ilbc/anaFilter.h pjproject/third_party/ilbc/StateConstructW.c pjproject/third_party/ilbc/StateConstructW.h pjproject/third_party/ilbc/filter.c pjproject/third_party/ilbc/filter.h pjproject/third_party/ilbc/gainquant.c pjproject/third_party/ilbc/gainquant.h pjproject/third_party/ilbc/FrameClassify.c pjproject/third_party/ilbc/FrameClassify.h pjproject/third_party/ilbc/doCPLC.c pjproject/third_party/ilbc/doCPLC.h pjproject/third_party/ilbc/hpInput.c pjproject/third_party/ilbc/hpInput.h pjproject/third_party/ilbc/iLBC_test.c pjproject/third_party/ilbc/LPCencode.c pjproject/third_party/ilbc/LPCencode.h pjproject/third_party/ilbc/iCBSearch.c pjproject/third_party/ilbc/iCBSearch.h pjproject/third_party/ilbc/LPCdecode.c pjproject/third_party/ilbc/LPCdecode.h pjproject/third_party/ilbc/packing.c pjproject/third_party/ilbc/packing.h pjproject/third_party/ilbc/getCBvec.c pjproject/third_party/ilbc/getCBvec.h pjproject/third_party/ilbc/iLBC_encode.c pjproject/third_party/ilbc/iLBC_encode.h pjproject/third_party/ilbc/StateSearchW.c pjproject/third_party/ilbc/StateSearchW.h pjproject/third_party/ilbc/helpfun.c pjproject/third_party/ilbc/helpfun.h pjproject/third_party/ilbc/syntFilter.c pjproject/third_party/ilbc/syntFilter.h pjproject/third_party/ilbc/hpOutput.c pjproject/third_party/ilbc/hpOutput.h pjproject/third_party/ilbc/iLBC_decode.c pjproject/third_party/ilbc/iLBC_decode.h pjproject/third_party/build/gsm/Makefile pjproject/third_party/build/gsm/libgsmcodec.vcproj pjproject/third_party/build/gsm/config.h pjproject/third_party/build/gsm/libgsmcodec.dsp pjproject/third_party/build/gsm/libgsmcodec.vcp pjproject/third_party/build/ilbc/Makefile pjproject/third_party/build/ilbc/libilbccodec.vcproj pjproject/third_party/build/ilbc/libilbccodec.dsp pjproject/third_party/build/ilbc/libilbccodec.vcp pjproject/third_party/build/os-darwinos.mak pjproject/third_party/build/Makefile pjproject/third_party/build/os-auto.mak.in pjproject/third_party/build/resample/libresample_dll.dsp pjproject/third_party/build/resample/Makefile pjproject/third_party/build/resample/libresample.dsp pjproject/third_party/build/resample/libresample.vcp pjproject/third_party/build/resample/libresample.vcproj pjproject/third_party/build/resample/config.h pjproject/third_party/build/resample/libresample_dll.vcproj pjproject/third_party/build/speex/Makefile pjproject/third_party/build/speex/speex/speex_config_types.h pjproject/third_party/build/speex/libspeex.dsp pjproject/third_party/build/speex/libspeex.vcp pjproject/third_party/build/speex/libspeex.vcproj pjproject/third_party/build/speex/config.h pjproject/third_party/build/os-auto.mak pjproject/third_party/build/os-linux.mak pjproject/third_party/build/samplerate/Static.msvc pjproject/third_party/build/samplerate/README.txt pjproject/third_party/build/samplerate/libsamplerate_static.dsp pjproject/third_party/build/portaudio/src/pa_allocation.c pjproject/third_party/build/portaudio/src/pa_allocation.h pjproject/third_party/build/portaudio/src/pa_unix_oss.c pjproject/third_party/build/portaudio/src/pa_unix_hostapis.c pjproject/third_party/build/portaudio/src/pa_linux_alsa.c pjproject/third_party/build/portaudio/src/pa_linux_alsa.h pjproject/third_party/build/portaudio/src/pa_endianness.h pjproject/third_party/build/portaudio/src/pa_process.c pjproject/third_party/build/portaudio/src/pa_process.h pjproject/third_party/build/portaudio/src/pa_mac_core_blocking.c pjproject/third_party/build/portaudio/src/pa_mac_core_blocking.h pjproject/third_party/build/portaudio/src/pa_ringbuffer.c pjproject/third_party/build/portaudio/src/pa_ringbuffer.h pjproject/third_party/build/portaudio/src/pa_win_hostapis.c pjproject/third_party/build/portaudio/src/pa_util.h pjproject/third_party/build/portaudio/src/pa_win_util.c pjproject/third_party/build/portaudio/src/pa_win_wmme.c pjproject/third_party/build/portaudio/src/pa_win_wmme.h pjproject/third_party/build/portaudio/src/pa_unix_util.c pjproject/third_party/build/portaudio/src/pa_unix_util.h pjproject/third_party/build/portaudio/src/pa_mac_core.c pjproject/third_party/build/portaudio/src/pa_mac_core.h pjproject/third_party/build/portaudio/src/pa_hostapi.h pjproject/third_party/build/portaudio/src/pa_cpuload.c pjproject/third_party/build/portaudio/src/pa_cpuload.h pjproject/third_party/build/portaudio/src/pa_stream.c pjproject/third_party/build/portaudio/src/pa_stream.h pjproject/third_party/build/portaudio/src/pa_mac_core_internal.h pjproject/third_party/build/portaudio/src/pa_converters.c pjproject/third_party/build/portaudio/src/pa_converters.h pjproject/third_party/build/portaudio/src/pa_debugprint.c pjproject/third_party/build/portaudio/src/pa_debugprint.h pjproject/third_party/build/portaudio/src/pa_mac_core_old.c pjproject/third_party/build/portaudio/src/pa_front.c pjproject/third_party/build/portaudio/src/pa_skeleton.c pjproject/third_party/build/portaudio/src/pa_trace.c pjproject/third_party/build/portaudio/src/pa_trace.h pjproject/third_party/build/portaudio/src/pa_mac_core_utilities.c pjproject/third_party/build/portaudio/src/pa_mac_core_utilities.h pjproject/third_party/build/portaudio/src/pa_mac_hostapis.c pjproject/third_party/build/portaudio/src/portaudio.h pjproject/third_party/build/portaudio/src/pa_dither.c pjproject/third_party/build/portaudio/src/pa_dither.h pjproject/third_party/build/portaudio/src/pa_types.h pjproject/third_party/build/portaudio/Makefile pjproject/third_party/build/portaudio/os-auto.mak.in pjproject/third_party/build/portaudio/os-auto.mak pjproject/third_party/build/portaudio/os-linux.mak pjproject/third_party/build/portaudio/libportaudio.vcproj pjproject/third_party/build/portaudio/libportaudio.dsp pjproject/third_party/build/portaudio/libportaudio.vcp pjproject/third_party/build/milenage/Makefile pjproject/third_party/build/milenage/libmilenage.dsp pjproject/third_party/build/milenage/libmilenage.vcp pjproject/third_party/build/milenage/libmilenage.vcproj pjproject/third_party/build/os-win32.mak pjproject/third_party/resample/src/stddefs.h pjproject/third_party/resample/src/smallfilter.h pjproject/third_party/resample/src/libresample_dll.c pjproject/third_party/resample/src/largefilter.h pjproject/third_party/resample/src/resamplesubs.c pjproject/third_party/resample/src/resample.h pjproject/third_party/resample/README.resample pjproject/third_party/resample/include/resamplesubs.h pjproject/third_party/resample/COPYING pjproject/third_party/speex/ti/testenc-TI-C5x.c pjproject/third_party/speex/ti/testenc-TI-C64x.c pjproject/third_party/speex/ti/config.h pjproject/third_party/speex/ti/speex_C54_test/speex_C54_test.pjt pjproject/third_party/speex/ti/user_misc.h pjproject/third_party/speex/ti/speex_C55_test/speex_C55_test.pjt pjproject/third_party/speex/ti/speex_C64_test/speex_C64_test.pjt pjproject/third_party/speex/doc/REMOVED_BY_PJSIP pjproject/third_party/speex/src/wave_out.c pjproject/third_party/speex/src/wave_out.h pjproject/third_party/speex/src/getopt.c pjproject/third_party/speex/src/getopt1.c pjproject/third_party/speex/src/wav_io.c pjproject/third_party/speex/src/wav_io.h pjproject/third_party/speex/src/skeleton.c pjproject/third_party/speex/src/skeleton.h pjproject/third_party/speex/src/speexdec.1 pjproject/third_party/speex/src/speexdec.c pjproject/third_party/speex/src/speexenc.1 pjproject/third_party/speex/src/speexenc.c pjproject/third_party/speex/src/getopt_win.h pjproject/third_party/speex/tmv/misc_tm.h pjproject/third_party/speex/tmv/preprocess_tm.h pjproject/third_party/speex/tmv/profile_tm.h pjproject/third_party/speex/tmv/quant_lsp_tm.h pjproject/third_party/speex/tmv/kiss_fft_tm.h pjproject/third_party/speex/tmv/kiss_fftr_tm.h pjproject/third_party/speex/tmv/_kiss_fft_guts_tm.h pjproject/third_party/speex/tmv/lsp_tm.h pjproject/third_party/speex/tmv/config.h pjproject/third_party/speex/tmv/ltp_tm.h pjproject/third_party/speex/tmv/fixed_tm.h pjproject/third_party/speex/tmv/mdf_tm.h pjproject/third_party/speex/tmv/vq_tm.h pjproject/third_party/speex/tmv/cb_search_tm.h pjproject/third_party/speex/tmv/lpc_tm.h pjproject/third_party/speex/tmv/fftwrap_tm.h pjproject/third_party/speex/tmv/filters_tm.h pjproject/third_party/speex/tmv/speex_config_types.h pjproject/third_party/speex/tmv/filterbank_tm.h pjproject/third_party/speex/NEWS pjproject/third_party/speex/TODO pjproject/third_party/speex/html/speex.webprj pjproject/third_party/speex/html/index.html pjproject/third_party/speex/html/patents.html pjproject/third_party/speex/html/speex.png pjproject/third_party/speex/html/speex.xcf pjproject/third_party/speex/speexclient/alsa_device.c pjproject/third_party/speex/speexclient/alsa_device.h pjproject/third_party/speex/speexclient/README pjproject/third_party/speex/speexclient/compile.sh pjproject/third_party/speex/speexclient/speexclient.c pjproject/third_party/speex/IDEAS pjproject/third_party/speex/Speex.spec.in pjproject/third_party/speex/win32/speexdec/speexdec.dsp pjproject/third_party/speex/win32/speexdec/speexdec.dsw pjproject/third_party/speex/win32/speexenc/speexenc.dsp pjproject/third_party/speex/win32/speexenc/speexenc.dsw pjproject/third_party/speex/win32/VS2003/speexdec/speexdec.vcproj pjproject/third_party/speex/win32/VS2003/speexenc/speexenc.vcproj pjproject/third_party/speex/win32/VS2003/libspeex/libspeex.def pjproject/third_party/speex/win32/VS2003/libspeex/libspeex.vcproj pjproject/third_party/speex/win32/VS2005/speexdec/speexdec.vcproj pjproject/third_party/speex/win32/VS2005/speexenc/speexenc.vcproj pjproject/third_party/speex/win32/VS2005/libspeex/libspeex.vcproj pjproject/third_party/speex/win32/config.h pjproject/third_party/speex/win32/speex.iss pjproject/third_party/speex/win32/libspeex/libspeex.dsp pjproject/third_party/speex/win32/libspeex/libspeex.dsw pjproject/third_party/speex/win32/libspeex/libspeex_dynamic.dsp pjproject/third_party/speex/win32/libspeex/speex.def pjproject/third_party/speex/speex.m4 pjproject/third_party/speex/README pjproject/third_party/speex/README.Trimedia pjproject/third_party/speex/speex.pc.in pjproject/third_party/speex/autogen.sh pjproject/third_party/speex/OPTIMIZE pjproject/third_party/speex/symbian/config.h pjproject/third_party/speex/symbian/speex.mmp pjproject/third_party/speex/symbian/bld.inf pjproject/third_party/speex/README.symbian pjproject/third_party/speex/README.win32 pjproject/third_party/speex/macosx/Speex_Prefix.pch pjproject/third_party/speex/macosx/Speex_UB.xcodeproj/project.pbxproj pjproject/third_party/speex/macosx/Speex.xcodeproj/project.pbxproj pjproject/third_party/speex/macosx/English.lproj/InfoPlist.strings pjproject/third_party/speex/macosx/Info.plist pjproject/third_party/speex/acinclude.m4 pjproject/third_party/speex/AUTHORS pjproject/third_party/speex/README.TI-DSP pjproject/third_party/speex/INSTALL pjproject/third_party/speex/Speex.kdevelop pjproject/third_party/speex/README.blackfin pjproject/third_party/speex/libspeex/_kiss_fft_guts.h pjproject/third_party/speex/libspeex/cb_search.c pjproject/third_party/speex/libspeex/cb_search.h pjproject/third_party/speex/libspeex/vq.c pjproject/third_party/speex/libspeex/vq.h pjproject/third_party/speex/libspeex/vq_sse.h pjproject/third_party/speex/libspeex/exc_5_64_table.c pjproject/third_party/speex/libspeex/cb_search_bfin.h pjproject/third_party/speex/libspeex/cb_search_arm4.h pjproject/third_party/speex/libspeex/math_approx.c pjproject/third_party/speex/libspeex/math_approx.h pjproject/third_party/speex/libspeex/testenc_wb.c pjproject/third_party/speex/libspeex/gain_table_lbr.c pjproject/third_party/speex/libspeex/cb_search_sse.h pjproject/third_party/speex/libspeex/testecho.c pjproject/third_party/speex/libspeex/mdf.c pjproject/third_party/speex/libspeex/lpc.c pjproject/third_party/speex/libspeex/lpc.h pjproject/third_party/speex/libspeex/lsp.c pjproject/third_party/speex/libspeex/lsp.h pjproject/third_party/speex/libspeex/ltp.c pjproject/third_party/speex/libspeex/ltp.h pjproject/third_party/speex/libspeex/filters_bfin.h pjproject/third_party/speex/libspeex/fixed_debug.h pjproject/third_party/speex/libspeex/misc_bfin.h pjproject/third_party/speex/libspeex/filters_arm4.h pjproject/third_party/speex/libspeex/vbr.c pjproject/third_party/speex/libspeex/vbr.h pjproject/third_party/speex/libspeex/vq_bfin.h pjproject/third_party/speex/libspeex/vq_arm4.h pjproject/third_party/speex/libspeex/vorbis_psy.c pjproject/third_party/speex/libspeex/vorbis_psy.h pjproject/third_party/speex/libspeex/exc_10_32_table.c pjproject/third_party/speex/libspeex/lsp_bfin.h pjproject/third_party/speex/libspeex/quant_lsp_bfin.h pjproject/third_party/speex/libspeex/preprocess.c pjproject/third_party/speex/libspeex/filters.c pjproject/third_party/speex/libspeex/filters.h pjproject/third_party/speex/libspeex/fixed_generic.h pjproject/third_party/speex/libspeex/exc_5_256_table.c pjproject/third_party/speex/libspeex/gain_table.c pjproject/third_party/speex/libspeex/stack_alloc.h pjproject/third_party/speex/libspeex/quant_lsp.c pjproject/third_party/speex/libspeex/quant_lsp.h pjproject/third_party/speex/libspeex/pseudofloat.h pjproject/third_party/speex/libspeex/speex.c pjproject/third_party/speex/libspeex/kiss_fftr.c pjproject/third_party/speex/libspeex/kiss_fftr.h pjproject/third_party/speex/libspeex/smallft.c pjproject/third_party/speex/libspeex/smallft.h pjproject/third_party/speex/libspeex/sb_celp.c pjproject/third_party/speex/libspeex/sb_celp.h pjproject/third_party/speex/libspeex/lbr_48k_tables.c pjproject/third_party/speex/libspeex/arch.h pjproject/third_party/speex/libspeex/bits.c pjproject/third_party/speex/libspeex/exc_20_32_table.c pjproject/third_party/speex/libspeex/testdenoise.c pjproject/third_party/speex/libspeex/speex_callbacks.c pjproject/third_party/speex/libspeex/nb_celp.c pjproject/third_party/speex/libspeex/nb_celp.h pjproject/third_party/speex/libspeex/modes.c pjproject/third_party/speex/libspeex/modes.h pjproject/third_party/speex/libspeex/filters_sse.h pjproject/third_party/speex/libspeex/speex_header.c pjproject/third_party/speex/libspeex/hexc_10_32_table.c pjproject/third_party/speex/libspeex/misc.c pjproject/third_party/speex/libspeex/misc.h pjproject/third_party/speex/libspeex/testenc_uwb.c pjproject/third_party/speex/libspeex/ltp_sse.h pjproject/third_party/speex/libspeex/lpc_bfin.h pjproject/third_party/speex/libspeex/window.c pjproject/third_party/speex/libspeex/high_lsp_tables.c pjproject/third_party/speex/libspeex/fftwrap.c pjproject/third_party/speex/libspeex/fftwrap.h pjproject/third_party/speex/libspeex/exc_8_128_table.c pjproject/third_party/speex/libspeex/filterbank.c pjproject/third_party/speex/libspeex/filterbank.h pjproject/third_party/speex/libspeex/lsp_tables_nb.c pjproject/third_party/speex/libspeex/stereo.c pjproject/third_party/speex/libspeex/ltp_bfin.h pjproject/third_party/speex/libspeex/ltp_arm4.h pjproject/third_party/speex/libspeex/fixed_bfin.h pjproject/third_party/speex/libspeex/fixed_arm4.h pjproject/third_party/speex/libspeex/echo_diagnostic.m pjproject/third_party/speex/libspeex/kiss_fft.c pjproject/third_party/speex/libspeex/kiss_fft.h pjproject/third_party/speex/libspeex/testresample.c pjproject/third_party/speex/libspeex/jitter.c pjproject/third_party/speex/libspeex/fixed_arm5e.h pjproject/third_party/speex/libspeex/hexc_table.c pjproject/third_party/speex/libspeex/testenc.c pjproject/third_party/speex/libspeex/medfilter.c pjproject/third_party/speex/libspeex/medfilter.h pjproject/third_party/speex/libspeex/exc_10_16_table.c pjproject/third_party/speex/libspeex/resample.c pjproject/third_party/speex/ChangeLog pjproject/third_party/speex/include/speex/speex_echo.h pjproject/third_party/speex/include/speex/speex_config_types.h.in pjproject/third_party/speex/include/speex/speex.h pjproject/third_party/speex/include/speex/speex_stereo.h pjproject/third_party/speex/include/speex/speex_callbacks.h pjproject/third_party/speex/include/speex/speex_header.h pjproject/third_party/speex/include/speex/speex_jitter.h pjproject/third_party/speex/include/speex/speex_resampler.h pjproject/third_party/speex/include/speex/speex_types.h pjproject/third_party/speex/include/speex/speex_preprocess.h pjproject/third_party/speex/include/speex/speex_bits.h pjproject/third_party/speex/COPYING pjproject/third_party/speex/Doxyfile pjproject/third_party/portaudio/doc/src/mainpage.dox pjproject/third_party/portaudio/doc/src/srcguide.dox pjproject/third_party/portaudio/doc/src/license.dox pjproject/third_party/portaudio/doc/utils/checkfiledocs.py pjproject/third_party/portaudio/src/os/win/pa_x86_plain_converters.c pjproject/third_party/portaudio/src/os/win/pa_x86_plain_converters.h pjproject/third_party/portaudio/src/os/win/pa_win_hostapis.c pjproject/third_party/portaudio/src/os/win/pa_win_util.c pjproject/third_party/portaudio/src/os/unix/pa_unix_hostapis.c pjproject/third_party/portaudio/src/os/unix/pa_unix_util.c pjproject/third_party/portaudio/src/os/unix/pa_unix_util.h pjproject/third_party/portaudio/src/os/mac_osx/pa_mac_hostapis.c pjproject/third_party/portaudio/src/SConscript pjproject/third_party/portaudio/src/common/pa_allocation.c pjproject/third_party/portaudio/src/common/pa_allocation.h pjproject/third_party/portaudio/src/common/pa_endianness.h pjproject/third_party/portaudio/src/common/pa_process.c pjproject/third_party/portaudio/src/common/pa_process.h pjproject/third_party/portaudio/src/common/pa_ringbuffer.c pjproject/third_party/portaudio/src/common/pa_ringbuffer.h pjproject/third_party/portaudio/src/common/pa_util.h pjproject/third_party/portaudio/src/common/pa_hostapi.h pjproject/third_party/portaudio/src/common/pa_cpuload.c pjproject/third_party/portaudio/src/common/pa_cpuload.h pjproject/third_party/portaudio/src/common/pa_stream.c pjproject/third_party/portaudio/src/common/pa_stream.h pjproject/third_party/portaudio/src/common/pa_converters.c pjproject/third_party/portaudio/src/common/pa_converters.h pjproject/third_party/portaudio/src/common/pa_debugprint.c pjproject/third_party/portaudio/src/common/pa_debugprint.h pjproject/third_party/portaudio/src/common/pa_front.c pjproject/third_party/portaudio/src/common/pa_skeleton.c pjproject/third_party/portaudio/src/common/pa_trace.c pjproject/third_party/portaudio/src/common/pa_trace.h pjproject/third_party/portaudio/src/common/pa_dither.c pjproject/third_party/portaudio/src/common/pa_dither.h pjproject/third_party/portaudio/src/common/pa_types.h pjproject/third_party/portaudio/src/hostapi/oss/pa_unix_oss.c pjproject/third_party/portaudio/src/hostapi/oss/recplay.c pjproject/third_party/portaudio/src/hostapi/oss/low_latency_tip.txt pjproject/third_party/portaudio/src/hostapi/alsa/pa_linux_alsa.c pjproject/third_party/portaudio/src/hostapi/asio/pa_asio.cpp pjproject/third_party/portaudio/src/hostapi/asio/iasiothiscallresolver.h pjproject/third_party/portaudio/src/hostapi/asio/Callback_adaptation_.pdf pjproject/third_party/portaudio/src/hostapi/asio/Pa_ASIO.pdf pjproject/third_party/portaudio/src/hostapi/asio/iasiothiscallresolver.cpp pjproject/third_party/portaudio/src/hostapi/asio/ASIO-README.txt pjproject/third_party/portaudio/src/hostapi/jack/pa_jack.c pjproject/third_party/portaudio/src/hostapi/wmme/pa_win_wmme.c pjproject/third_party/portaudio/src/hostapi/wdmks/readme.txt pjproject/third_party/portaudio/src/hostapi/wdmks/pa_win_wdmks.c pjproject/third_party/portaudio/src/hostapi/asihpi/pa_linux_asihpi.c pjproject/third_party/portaudio/src/hostapi/dsound/pa_win_ds.c pjproject/third_party/portaudio/src/hostapi/dsound/pa_win_ds_dynlink.c pjproject/third_party/portaudio/src/hostapi/dsound/pa_win_ds_dynlink.h pjproject/third_party/portaudio/src/hostapi/wasapi/pa_win_wasapi.cpp pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core_blocking.c pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core_blocking.h pjproject/third_party/portaudio/src/hostapi/coreaudio/notes.txt pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core.c pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core_internal.h pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core_old.c pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core_utilities.c pjproject/third_party/portaudio/src/hostapi/coreaudio/pa_mac_core_utilities.h pjproject/third_party/portaudio/bindings/cpp/REMOVED_BY_PJSIP pjproject/third_party/portaudio/test/REMOVED_BY_PJSIP pjproject/third_party/portaudio/depcomp pjproject/third_party/portaudio/SConstruct pjproject/third_party/portaudio/build/msvc/portaudio.def pjproject/third_party/portaudio/build/msvc/portaudio.dsp pjproject/third_party/portaudio/build/msvc/portaudio.dsw pjproject/third_party/portaudio/build/msvc/portaudio.sln pjproject/third_party/portaudio/build/msvc/portaudio.vcproj pjproject/third_party/portaudio/build/msvc/readme.txt pjproject/third_party/portaudio/build/dev-cpp/portaudio-static.dev pjproject/third_party/portaudio/build/dev-cpp/Makefile-static pjproject/third_party/portaudio/build/dev-cpp/readme.txt pjproject/third_party/portaudio/build/dev-cpp/Makefile-dll pjproject/third_party/portaudio/build/dev-cpp/portaudio-dll.dev pjproject/third_party/portaudio/build/scons/SConscript_common pjproject/third_party/portaudio/build/scons/SConscript_opts pjproject/third_party/portaudio/aclocal.m4 pjproject/third_party/portaudio/Makefile.darwin pjproject/third_party/portaudio/fixfile.bat pjproject/third_party/portaudio/ltmain.sh pjproject/third_party/portaudio/configure pjproject/third_party/portaudio/configure.in pjproject/third_party/portaudio/index.html pjproject/third_party/portaudio/config.guess pjproject/third_party/portaudio/install-sh pjproject/third_party/portaudio/testcvs/changeme.txt pjproject/third_party/portaudio/config.sub pjproject/third_party/portaudio/missing pjproject/third_party/portaudio/Makefile.in pjproject/third_party/portaudio/fixdir.bat pjproject/third_party/portaudio/LICENSE.txt pjproject/third_party/portaudio/pablio/pablio.c pjproject/third_party/portaudio/pablio/pablio.h pjproject/third_party/portaudio/pablio/test_w_saw8.c pjproject/third_party/portaudio/pablio/test_rw_echo.c pjproject/third_party/portaudio/pablio/pablio.def pjproject/third_party/portaudio/pablio/README.txt pjproject/third_party/portaudio/pablio/test_w_saw.c pjproject/third_party/portaudio/pablio/test_rw.c pjproject/third_party/portaudio/README.txt pjproject/third_party/portaudio/COMPILING.DARWIN pjproject/third_party/portaudio/V19-devel-readme.txt pjproject/third_party/portaudio/portaudio-2.0.pc.in pjproject/third_party/portaudio/include/pa_asio.h pjproject/third_party/portaudio/include/pa_linux_alsa.h pjproject/third_party/portaudio/include/pa_win_wmme.h pjproject/third_party/portaudio/include/pa_mac_core.h pjproject/third_party/portaudio/include/portaudio.h pjproject/third_party/portaudio/Doxyfile pjproject/third_party/milenage/milenage.c pjproject/third_party/milenage/milenage.h pjproject/third_party/milenage/rijndael.c pjproject/third_party/milenage/rijndael.h pjproject/third_party/README.txt pjproject/COPYING pjproject/pjlib-util/src/pjlib-util-test/xml.c pjproject/pjlib-util/src/pjlib-util-test/resolver_test.c pjproject/pjlib-util/src/pjlib-util-test/main.c pjproject/pjlib-util/src/pjlib-util-test/test.c pjproject/pjlib-util/src/pjlib-util-test/test.h pjproject/pjlib-util/src/pjlib-util-test/stun.c pjproject/pjlib-util/src/pjlib-util-test/encryption.c pjproject/pjlib-util/src/pjlib-util-test/main_rtems.c pjproject/pjlib-util/src/pjlib-util/resolver.c pjproject/pjlib-util/src/pjlib-util/stun_simple.c pjproject/pjlib-util/src/pjlib-util/crc32.c pjproject/pjlib-util/src/pjlib-util/dns_dump.c pjproject/pjlib-util/src/pjlib-util/dns.c pjproject/pjlib-util/src/pjlib-util/md5.c pjproject/pjlib-util/src/pjlib-util/xml.c pjproject/pjlib-util/src/pjlib-util/hmac_md5.c pjproject/pjlib-util/src/pjlib-util/stun_simple_client.c pjproject/pjlib-util/src/pjlib-util/symbols.c pjproject/pjlib-util/src/pjlib-util/hmac_sha1.c pjproject/pjlib-util/src/pjlib-util/errno.c pjproject/pjlib-util/src/pjlib-util/srv_resolver.c pjproject/pjlib-util/src/pjlib-util/scanner.c pjproject/pjlib-util/src/pjlib-util/getopt.c pjproject/pjlib-util/src/pjlib-util/scanner_cis_bitwise.c pjproject/pjlib-util/src/pjlib-util/sha1.c pjproject/pjlib-util/src/pjlib-util/scanner_cis_uint.c pjproject/pjlib-util/src/pjlib-util/base64.c pjproject/pjlib-util/src/pjlib-util/string.c pjproject/pjlib-util/docs/doxygen.cfg pjproject/pjlib-util/docs/doxygen.css pjproject/pjlib-util/docs/footer.html pjproject/pjlib-util/docs/header.html pjproject/pjlib-util/build/Makefile pjproject/pjlib-util/build/os-auto.mak.in pjproject/pjlib-util/build/os-rtems.mak pjproject/pjlib-util/build/os-auto.mak pjproject/pjlib-util/build/pjlib_util.dsp pjproject/pjlib-util/build/pjlib_util.dsw pjproject/pjlib-util/build/pjlib_util.vcproj pjproject/pjlib-util/build/wince-evc4/pjlib_util_wince.vcp pjproject/pjlib-util/build/wince-evc4/pjlib_util_wince.vcw pjproject/pjlib-util/build/pjlib_util_test.dsp pjproject/pjlib-util/build/pjlib_util_test.vcproj pjproject/pjlib-util/include/pjlib-util.h pjproject/pjlib-util/include/pjlib-util/resolver.h pjproject/pjlib-util/include/pjlib-util/stun_simple.h pjproject/pjlib-util/include/pjlib-util/crc32.h pjproject/pjlib-util/include/pjlib-util/dns.h pjproject/pjlib-util/include/pjlib-util/md5.h pjproject/pjlib-util/include/pjlib-util/xml.h pjproject/pjlib-util/include/pjlib-util/hmac_md5.h pjproject/pjlib-util/include/pjlib-util/hmac_sha1.h pjproject/pjlib-util/include/pjlib-util/errno.h pjproject/pjlib-util/include/pjlib-util/srv_resolver.h pjproject/pjlib-util/include/pjlib-util/scanner.h pjproject/pjlib-util/include/pjlib-util/config.h pjproject/pjlib-util/include/pjlib-util/getopt.h pjproject/pjlib-util/include/pjlib-util/scanner_cis_bitwise.h pjproject/pjlib-util/include/pjlib-util/types.h pjproject/pjlib-util/include/pjlib-util/sha1.h pjproject/pjlib-util/include/pjlib-util/scanner_cis_uint.h pjproject/pjlib-util/include/pjlib-util/base64.h pjproject/pjlib-util/include/pjlib-util/string.h pjproject/user.mak")
  
  AC_SUBST(hipl_common_include_paths, "-I $HIPL -I $HIPL_HIPD -I $HIPL_LIBINET6 -I $HIPL_LIBINET6_INCLUDE -I $HIPL_LIBHIPTOOL -I $HIPL_LIBOPPHIP -I $HIPL_TOOLS -I $HIPL_OPENDHT -I $HIPL_LIBIPSEC -I $HIPL_I3 -I $HIPL_I3_CLIENT -I $HIPL_AESHASH -I $HIPL_I3_CHORD -I $HIPL_I3_UTILS -I $HIPL_PJPROJECT_LIB/include -I $HIPL_PJPROJECT_LIB_UTIL/include -I $HIPL_PJPROJECT_NATH/include -I $HIPL_PJPROJECT_MEDIA/include -I $HIPL_PJPROJECT_SIP/include")
  

AC_SUBST(hipl_common_include_paths, "-I $HIPL -I $HIPL_HIPD -I $HIPL_LIBINET6 -I $HIPL_LIBINET6_INCLUDE -I $HIPL_LIBHIPTOOL -I $HIPL_LIBOPPHIP -I $HIPL_TOOLS -I $HIPL_OPENDHT -I $HIPL_LIBIPSEC -I $HIPL_I3 -I $HIPL_I3_CLIENT -I $HIPL_AESHASH -I $HIPL_I3_CHORD -I $HIPL_I3_UTILS -I $HIPL_PJPROJECT_LIB/include -I $HIPL_PJPROJECT_LIB_UTIL/include -I $HIPL_PJPROJECT_NATH/include -I $HIPL_PJPROJECT_MEDIA/include -I $HIPL_PJPROJECT_SIP/include -I $HIPL_PERFORMANCE")

AC_SUBST(hipl_common_cflags, "$OPENWRT_CFLAGS $GDB_CFLAG $XMLI")

AC_CONFIG_FILES([ Makefile
                  libhiptool/Makefile
                  libinet6/Makefile
                  libinet6/include_glibc21/Makefile
                  libinet6/include_glibc22/Makefile
                  libinet6/include_glibc23/Makefile
                  libopphip/Makefile
                  opendht/Makefile
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

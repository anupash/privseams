
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Generated with autoscan and manually edited -Miika

AC_PREREQ([2.53])
AC_INIT([HIP for Linux], [main], [hipl-users@freelists.org], [hipl])
AC_CONFIG_SRCDIR([tools/hipconftool.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL(disable-shared)

# Check for python for tools directory
AM_PATH_PYTHON([2.4.3],, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

# Checks for libraries.
AC_CHECK_LIB(crypto, DSA_generate_key,, AC_MSG_ERROR(openssl lib not found))
# We need the math lib in the registration extension.
AC_CHECK_LIB(m, pow,, AC_MSG_ERROR(Math lib not found))

# Checks for header files.
# libintl.h and alloca.h are only used in libhipandroid/regex.c - remove if possible
AC_CHECK_HEADERS([alloca.h libintl.h])

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

# If no --prefix option is passed to configure, $prefix is empty. But we want
# to expand $sysconfdir, which defaults to ${prefix}/etc. So set $prefix.
if test "x$prefix" = "xNONE"; then
    prefix="$ac_default_prefix"
fi

AC_DEFINE_UNQUOTED(HIPL_DEFAULT_PREFIX, "$(eval echo ${prefix})")
AH_TEMPLATE(HIPL_DEFAULT_PREFIX, [default prefix])

# Default sysconf and lockfile directory
# TODO: @Miika is there any better way to define this?
AC_SUBST(sysconfdir, /etc/hip/)
AC_DEFINE_UNQUOTED(HIPL_SYSCONFDIR, "$(eval echo $sysconfdir)")
AH_TEMPLATE(HIPL_SYSCONFDIR, [default configuration file location])

AC_SUBST(lockdir, /var/lock/)
AC_DEFINE_UNQUOTED(HIPL_LOCKDIR, "$(eval echo $lockdir)")
AH_TEMPLATE(HIPL_LOCKDIR, [default lock file location])

AC_DEFINE_UNQUOTED(HIPL_HOSTS_FILE, "$(eval echo ${sysconfdir}hosts)")
AH_TEMPLATE(HIPL_HOSTS_FILE, [default hosts file location])

AC_DEFINE_UNQUOTED(HIPL_CONFIG_FILE, "$(eval echo ${sysconfdir}hipd_config)")
AH_TEMPLATE(HIPL_CONFIG_FILE, [default config file location])

glibc_version=2.3
usagi_libc=23
AC_SUBST(usagi_libc)

AC_ARG_ENABLE(firewall,
              AC_HELP_STRING([--enable-firewall],
                             [HIP enabled firewall daemon (default is YES)]),
             [ac_cv_use_firewall=$enableval],
             [ac_cv_use_firewall=yes])
AC_CACHE_CHECK([whether to use firewall],
               [ac_cv_use_firewall], [ac_cv_use_firewall=yes])
if test x"$ac_cv_use_firewall" = x"yes"; then
        AC_CHECK_LIB(ipq, ipq_create_handle,, [AC_MSG_ERROR([libipq not found])])
        AC_CHECK_LIB(config, config_setting_index,, [AC_MSG_WARN([libconfig not found, using default configuration of esp token extension])])
        AC_DEFINE(CONFIG_HIP_FIREWALL)
        AH_TEMPLATE(CONFIG_HIP_FIREWALL, [Defined to 1 if firewall is enabled.])
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
	AC_DEFINE(CONFIG_HIP_AGENT)
    AH_TEMPLATE(CONFIG_HIP_AGENT, [Defined to 1 if agent is enabled.])
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
        AC_DEFINE(CONFIG_HIP_COOKIE)
        AH_TEMPLATE(CONFIG_HIP_COOKIE, [Defined to 1 if cookie is enabled.])
fi

AC_ARG_ENABLE(pfkey,
             AC_HELP_STRING([--enable-pfkey],
                            [HIP pfkey extensions (default is NO)]),
             [ac_cv_use_pfkey=$enableval], [ac_cv_use_pfkey=no])
AC_CACHE_CHECK([whether to use pfkey extensions],
               [ac_cv_use_pfkey], [ac_cv_use_pfkey=no])
if test x"$ac_cv_use_pfkey" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PFKEY)
        AH_TEMPLATE(CONFIG_HIP_PFKEY, [Defined to 1 if pfkey is enabled.])
        AC_DEFINE(PATH_IPSEC_H, "netinet/ipsec.h")
        AH_TEMPLATE(PATH_IPSEC_H, [Path to ipsec.h.])
        AM_PROG_LEX
fi
AM_CONDITIONAL(HIP_PFKEY, test x"$ac_cv_use_pfkey" = x"yes")

AC_ARG_ENABLE(cert,
             AC_HELP_STRING([--enable-cert],
                            [Samus cert extensions (default is NO)]),
             [ac_cv_use_cert=$enableval], [ac_cv_use_cert=no])
AC_CACHE_CHECK([whether to use cert extensions],
               [ac_cv_use_cert], [ac_cv_use_cert=no])
if test x"$ac_cv_use_cert" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_CERT)
        AH_TEMPLATE(CONFIG_HIP_CERT, [Defined to 1 if certificates are enabled.])
fi

AC_ARG_ENABLE(rvs,
             AC_HELP_STRING([--enable-rvs],
                            [HIP Rendezvous Extensions (default is YES)]),
             [ac_cv_use_rvs=$enableval], [ac_cv_use_rvs=yes])
AC_CACHE_CHECK([whether to use RVS],
               [ac_cv_use_rvs], [ac_cv_use_rvs=yes])
if test x"$ac_cv_use_rvs" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_RVS)
        AH_TEMPLATE(CONFIG_HIP_RVS, [Defined to 1 if RVS is enabled.])
fi

AC_ARG_ENABLE(ice,
             AC_HELP_STRING([--enable-ice],
                            [ICE-based HIP NAT traversal extensions (default is YES)]),
             [ac_cv_use_ice=$enableval], [ac_cv_use_ice=yes])
AC_CACHE_CHECK([whether to use ICE],
               [ac_cv_use_ice], [ac_cv_use_ice=yes])
if test x"$ac_cv_use_ice" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ICE)
        AH_TEMPLATE(CONFIG_HIP_ICE, [Defined to 1 if ICE is enabled.])
fi
AM_CONDITIONAL(HIP_ICE, test x"$ac_cv_use_ice" = x"yes")

AC_ARG_ENABLE(hipproxy,
             AC_HELP_STRING([--enable-hipproxy],
                            [HIP Proxy (default is YES)]),
             [ac_cv_use_hipproxy=$enableval], [ac_cv_use_hipproxy=yes])
AC_CACHE_CHECK([whether to use HIP proxy],
               [ac_cv_use_hipproxy], [ac_cv_use_hipproxy=yes])
if test x"$ac_cv_use_hipproxy" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_HIPPROXY)
        AH_TEMPLATE(CONFIG_HIP_HIPPROXY, [Defined to 1 if the HIP Proxy is enabled.])
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
        AC_DEFINE(CONFIG_HIP_MAEMO)
        AH_TEMPLATE(CONFIG_HIP_MAEMO, [Defined to 1 if maemo build is enabled.])
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
        AC_DEFINE(CONFIG_HIP_OPENWRT)
        AC_SUBST(OPENWRT_CFLAGS, "-lc")
        AH_TEMPLATE(CONFIG_HIP_OPENWRT, [Defined to 1 if openwrt support is enabled.])
        if test x"$TARGET" = x"MIPS_LINUX"; then
                AC_DEFINE(CONFIG_HIP_OPENWRT_MIPSLINUX)
                AH_TEMPLATE(CONFIG_HIP_OPENWRT_MIPSLINUX, [Defined to 1 if mipslinux is enabled.])
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
        AC_DEFINE(CONFIG_HIP_ALTSEP)
        AH_TEMPLATE(CONFIG_HIP_ALTSEP, [Defined to 1 if alternative privilege separation is enabled.])
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
        AC_CHECK_LIB(xml2, xmlFreeDoc,, AC_MSG_ERROR(libxml2 not found))
        AC_CHECK_LIB(pthread, pthread_create,, AC_MSG_ERROR(libpthread not found))
        AC_DEFINE(CONFIG_HIP_I3)
        AH_TEMPLATE(CONFIG_HIP_I3, [Defined to 1 if i3 is enabled.])

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
        AC_DEFINE(CONFIG_HIP_PRIVSEP)
        AH_TEMPLATE(CONFIG_HIP_PRIVSEP, [Defined to 1 if privilege separation is enabled.])
fi
AM_CONDITIONAL(HIP_PRIVSEP, test x"$ac_cv_use_privsep" = x"yes")

AC_ARG_ENABLE(opportunistic,
             AC_HELP_STRING([--enable-opportunistic],
                            [HIP opportunistic extensions (default is YES)]),
             [ac_cv_use_opportunistic=$enableval], [ac_cv_use_opportunistic=yes])
AC_CACHE_CHECK([whether to use opportunistic],
               [ac_cv_use_opportunistic], [ac_cv_use_opportunistic=yes])
if test x"$ac_cv_use_opportunistic" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_OPPORTUNISTIC)
        AH_TEMPLATE(CONFIG_HIP_OPPORTUNISTIC, [Defined to 1 if oppotunistic mode is enabled.])
fi
AM_CONDITIONAL(HIP_OPPORTUNISTIC, test x"$ac_cv_use_opportunistic" = x"yes")

AC_ARG_ENABLE(savaipopt,
             AC_HELP_STRING([--enable-savaipoption],
                            [HIP SAVA IP option extensions, if no encrypt IP address (default is YES)]),
             [ac_cv_use_savaipopt=$enableval], [ac_cv_use_savaipopt=yes])
AC_CACHE_CHECK([whether to use sava ip option],
               [ac_cv_use_savaipopt], [ac_cv_use_savaipopt=yes])
if test x"$ac_cv_use_savaipopt" = x"yes"; then
        AC_DEFINE(CONFIG_SAVAH_IP_OPTION)
        AH_TEMPLATE(CONFIG_SAVAH_IP_OPTION, [Defined to 1 if SAVAH is enabled.])
fi
AM_CONDITIONAL(SAVAH_IP_OPTION, test x"$ac_cv_use_savaipopt" = x"yes")

AC_ARG_ENABLE(dht,
             AC_HELP_STRING([--enable-dht],
                            [DHT support (default is YES)]),
             [ac_cv_use_dht=$enableval], [ac_cv_use_dht=yes])
AC_CACHE_CHECK([whether to use dht],
               [ac_cv_use_dht], [ac_cv_use_dht=yes])
if test x"$ac_cv_use_dht" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_DHT)
        AH_TEMPLATE(CONFIG_HIP_DHT, [Defined to 1 if dht is enabled.])
        AC_CHECK_LIB(xml2, xmlFreeDoc,, AC_MSG_ERROR(libxml2 not found))
fi
AM_CONDITIONAL(HIP_DHT, test x"$ac_cv_use_dht" = x"yes")

AC_ARG_ENABLE(blind,
             AC_HELP_STRING([--enable-blind],
                            [HIP BLIND extensions (default is NO)]),
             [ac_cv_use_blind=$enableval], [ac_cv_use_blind=no])
AC_CACHE_CHECK([whether to use BLIND],
               [ac_cv_use_blind], [ac_cv_use_blind=no])
if test x"$ac_cv_use_blind" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_BLIND)
        AH_TEMPLATE(CONFIG_HIP_BLIND, [Defined to 1 if the blind extension is enabled.])
fi

AC_ARG_ENABLE(libinet6,
             AC_HELP_STRING([--enable-libinet6],
                            [Libinet6 output (default is NO)]),
             [ac_cv_use_libinet6=$enableval], [ac_cv_use_libinet6=no])
AC_CACHE_CHECK([whether to print output for libinet6s],
               [ac_cv_use_libinet6], [ac_cv_use_libinet6=yes])
if test x"$ac_cv_use_libinet6" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_LIBINET6)
        AH_TEMPLATE(CONFIG_HIP_LIBINET6, [Defined to 1 if unholy libinet6 crap is enabled.])
        AC_SUBST(HIPL_LIBINET6_INCLUDE, "$HIPL_LIBINET6/include")
else
        # Can't leave this undefined, otherwise build fails.
        # "." is always in the search path, we can just add it.
        AC_SUBST(HIPL_LIBINET6_INCLUDE, ".")
fi
AM_CONDITIONAL(HIP_LIBINET6, test x"$ac_cv_use_libinet6" = x"yes")

AC_ARG_ENABLE(profiling,
             AC_HELP_STRING([--enable-profiling],
                            [compile in gprof profiling support (default is NO)]),
             [ac_cv_use_profiling=$enableval], [ac_cv_use_profiling=no])
AC_CACHE_CHECK([whether to use grof support],
               [ac_cv_use_profiling], [ac_cv_use_profiling=no])
if test x"$ac_cv_use_profiling" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PROFILING)
        AH_TEMPLATE(CONFIG_HIP_PROFILING, [Defined to 1 if profiling is enabled.])
        AC_SUBST(GPROF_CFLAGS, "-pg")
fi
AM_CONDITIONAL(HIP_PROFILING, test x"$ac_cv_use_profiling" = x"yes")

AC_ARG_ENABLE(ecdsa,
             AC_HELP_STRING([--enable-ecdsa],
                            [compile in ecdsa support (default is NO)]),
             [ac_cv_use_ecdsa=$enableval], [ac_cv_use_ecdsa=no])
AC_CACHE_CHECK([whether to use ecdsa support],
               [ac_cv_use_ecdsa], [ac_cv_use_ecdsa=no])
if test x"$ac_cv_use_ecdsa" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ECDSA)
        AH_TEMPLATE(CONFIG_HIP_ECDSA, [Defined to 1 if ECDSA support is enabled.])
        AC_SUBST(GPROF_CFLAGS, "-pg")
fi
AM_CONDITIONAL(HIP_ECDSA, test x"$ac_cv_use_ecdsa" = x"yes")

AC_ARG_ENABLE(debug,
             AC_HELP_STRING([--enable-debug],
                            [Enable debug (default is YES)]),
             [ac_cv_use_debug=$enableval],
             [ac_cv_use_debug=yes])
AC_CACHE_CHECK([whether to have verbose debug],
               [ac_cv_use_debug], [ac_cv_use_debug=yes])
if test x"$ac_cv_use_debug" = x"yes"; then
        AC_DEFINE(HIP_LOGFMT_LONG)
        AH_TEMPLATE(HIP_LOGFMT_LONG, [Defined to 1 if long log format output is enabled.])
        AC_DEFINE(CONFIG_HIP_DEBUG)
        AH_TEMPLATE(CONFIG_HIP_DEBUG, [Defined to 1 if debug output is enabled.])
fi

AC_ARG_ENABLE(midauth,
             AC_HELP_STRING([--enable-midauth],
                            [Enable middlebox authentification (default is NO)]),
             [ac_cv_use_midauth=$enableval],
             [ac_cv_use_midauth=no])
AC_CACHE_CHECK([whether to have middlebox authentification],
               [ac_cv_use_midauth], [ac_cv_use_midauth=no])
if test x"$ac_cv_use_midauth" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_MIDAUTH)
        AH_TEMPLATE(CONFIG_HIP_MIDAUTH, [Defined to 1 if midauth extensions are enabled.])
fi
AM_CONDITIONAL(HIP_MIDAUTH, test x"$ac_cv_use_midauth" = x"yes")

AC_ARG_ENABLE(performance,
             AC_HELP_STRING([--enable-performance],
                            [Performace measurement support (default is NO)]),
             [ac_cv_use_performance=$enableval], [ac_cv_use_performance=no])
AC_CACHE_CHECK([whether to use performance measurement],
               [ac_cv_use_performance], [ac_cv_use_performance=no])
if test x"$ac_cv_use_performance" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_PERFORMANCE)
        AH_TEMPLATE(CONFIG_HIP_PERFORMANCE, [Defined to 1 if performance measurements are enabled.])
fi
AM_CONDITIONAL(HIP_PERFORMANCE, test x"$ac_cv_use_performance" = x"yes")

AC_ARG_ENABLE(demo,
             AC_HELP_STRING([--enable-demo],
                            [Demo output (default is NO)]),
             [ac_cv_use_demo=$enableval], [ac_cv_use_demo=no])
AC_CACHE_CHECK([whether to print output for demos],
               [ac_cv_use_demo], [ac_cv_use_demo=no])
if test x"$ac_cv_use_demo" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_DEMO)
        AH_TEMPLATE(CONFIG_HIP_DEMO, [Defined to 1 if demo is enabled.])
fi
AM_CONDITIONAL(HIP_DEMO, test x"$ac_cv_use_demo" = x"yes")

# Set default AM_CFLAGS for the complete project.
AC_SUBST(AM_CFLAGS, "-Werror -Wredundant-decls -Wall -Wcast-align -Wdisabled-optimization -Wundef -Wstrict-prototypes -Wno-deprecated-declarations -fno-strict-aliasing $OPENWRT_CFLAGS $GPROF_CFLAGS")

AC_CONFIG_FILES([ Makefile
                  libinet6/Makefile
                  libinet6/include_glibc21/Makefile
                  libinet6/include_glibc22/Makefile
                  libinet6/include_glibc23/Makefile])

AC_OUTPUT

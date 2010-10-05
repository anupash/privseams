AC_PREREQ([2.53])
AC_INIT([HIP for Linux], [1.0.6], [hipl-users@freelists.org], [hipl])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# This needs to be placed before AM_INIT_AUTOMAKE, otherwise $@ is modified.
# Note that the value of $@ changes if configure is rerun automatically during
# a rebuild. In this case "--no-create --no-recursion" appear to get passed to
# configure in addition to the stored command line options. Since this is a
# harmless sideeffect, it is ignored. Clean release builds should be made from
# a pristine tree.
AC_DEFINE_UNQUOTED(HIPL_CONFIGURATION, "$@")
AH_TEMPLATE(HIPL_CONFIGURATION, [options passed to configure])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
# AC_PROG_LIBTOOL() could be replaced with LT_INIT(disable-shared) but
# OpenWRT (Mar 2010) is running too old version of libtool
# LT_INIT(disable-shared)
AC_PROG_LIBTOOL(disable-shared)

AC_CHECK_PROG(have_xmlto, xmlto, yes)
AM_CONDITIONAL(HAVE_XMLTO, test x"$have_xmlto" = x"yes")

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_PROG_CC_C_O # Required in CentOS
# Enable silent rules only when available (automake 1.11 or later).
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Check for python for build-system and tools directory
AM_PATH_PYTHON([2.4.3],, [AC_MSG_ERROR([min. required python version not found])])

# Checks for libraries.
AC_CHECK_LIB(crypto, DSA_generate_key,, AC_MSG_ERROR(openssl lib not found))
# Check for ec crypto in openssl
AC_CHECK_FUNC(EC_KEY_new,
              AC_DEFINE(HAVE_EC_CRYPTO)
              AH_TEMPLATE(HAVE_EC_CRYPTO, [Defined to 1 if ec is enabled.]),)
# We need the math lib in the registration extension.
AC_CHECK_LIB(m, pow,, AC_MSG_ERROR(Math lib not found))

# If no --prefix option is passed to configure, $prefix is empty. But we want
# to expand $sysconfdir, which defaults to ${prefix}/etc. So set $prefix.
if test "x$prefix" = "xNONE"; then
    prefix="$ac_default_prefix"
fi

AC_DEFINE_UNQUOTED(HIPL_DEFAULT_PREFIX, "$(eval echo ${prefix})")
AH_TEMPLATE(HIPL_DEFAULT_PREFIX, [default prefix])

# Default sysconf and lockfile directory
# TODO: @Miika is there any better way to define this?
AC_SUBST(sysconfdir, /etc/hip)
AC_DEFINE_UNQUOTED(HIPL_SYSCONFDIR, "$(eval echo $sysconfdir)")
AH_TEMPLATE(HIPL_SYSCONFDIR, [default configuration file location])

AC_SUBST(lockdir, /var/lock/)
AC_DEFINE_UNQUOTED(HIPL_LOCKDIR, "$(eval echo $lockdir)")
AH_TEMPLATE(HIPL_LOCKDIR, [default lock file location])

AC_DEFINE_UNQUOTED(HIPL_HOSTS_FILE, "$(eval echo ${sysconfdir}hosts)")
AH_TEMPLATE(HIPL_HOSTS_FILE, [default hosts file location])

AC_DEFINE_UNQUOTED(HIPL_CONFIG_FILE, "$(eval echo ${sysconfdir}hipd_config)")
AH_TEMPLATE(HIPL_CONFIG_FILE, [default config file location])


AC_ARG_WITH(nomodules,
            AS_HELP_STRING([--with-nomodules=list],
                           [comma-separated list of disabled modules]))

# Set default AM_CFLAGS for the complete project.
AC_SUBST(AM_CFLAGS, "-std=c99 -Wall -Wextra -Werror")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wredundant-decls -Wdisabled-optimization")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wundef -Wstrict-prototypes -Wmissing-prototypes")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wno-deprecated-declarations -Wpointer-arith")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wwrite-strings -Wshadow -Winline -Wcast-qual")


#TODO fix the code and get rid of this one
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -fno-strict-aliasing")

# Set the preprocessor flags for the entire project
AC_SUBST(AM_CPPFLAGS, "-D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=500")

AC_ARG_ENABLE(firewall,
               AS_HELP_STRING([--enable-firewall],
                              [HIP enabled firewall daemon (default is YES)]),
               [ac_cv_use_firewall=$enableval],
               [ac_cv_use_firewall=yes])
AC_CACHE_CHECK([whether to use firewall],
               [ac_cv_use_firewall],
               [ac_cv_use_firewall=yes])
if test x"$ac_cv_use_firewall" = x"yes"; then
    AC_CHECK_LIB(ipq, ipq_create_handle,, [AC_MSG_ERROR([libipq not found])])
    AC_CHECK_LIB(config, config_setting_index,,
                 [AC_MSG_WARN([libconfig not found, using default config])])
    AC_DEFINE(CONFIG_HIP_FIREWALL)
    AH_TEMPLATE(CONFIG_HIP_FIREWALL, [Defined to 1 if firewall is enabled.])
fi
AM_CONDITIONAL(HIP_FIREWALL, test x"$ac_cv_use_firewall" = x"yes")

AC_ARG_ENABLE(rvs,
               AS_HELP_STRING([--enable-rvs],
                              [HIP Rendezvous Extensions (default is YES)]),
               [ac_cv_use_rvs=$enableval],
               [ac_cv_use_rvs=yes])
AC_CACHE_CHECK([whether to use RVS],
               [ac_cv_use_rvs],
               [ac_cv_use_rvs=yes])
if test x"$ac_cv_use_rvs" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_RVS)
    AH_TEMPLATE(CONFIG_HIP_RVS, [Defined to 1 if RVS is enabled.])
fi

AC_ARG_ENABLE(opportunistic,
               AS_HELP_STRING([--enable-opportunistic],
                              [HIP opportunistic mode (default is YES)]),
               [ac_cv_use_opportunistic=$enableval],
               [ac_cv_use_opportunistic=yes])
AC_CACHE_CHECK([whether to use opportunistic],
               [ac_cv_use_opportunistic],
               [ac_cv_use_opportunistic=yes])
if test x"$ac_cv_use_opportunistic" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_OPPORTUNISTIC)
    AH_TEMPLATE(CONFIG_HIP_OPPORTUNISTIC,
                [Defined to 1 if opportunistic mode is enabled.])
fi
AM_CONDITIONAL(HIP_OPPORTUNISTIC, test x"$ac_cv_use_opportunistic" = x"yes")

AC_ARG_ENABLE(profiling,
               AS_HELP_STRING([--enable-profiling],
                              [gprof profiling support (default is NO)]),
               [ac_cv_use_profiling=$enableval],
               [ac_cv_use_profiling=no])
AC_CACHE_CHECK([whether to use grof support],
               [ac_cv_use_profiling],
               [ac_cv_use_profiling=no])
if test x"$ac_cv_use_profiling" = x"yes"; then
    AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -pg")
fi

AC_ARG_ENABLE(debug,
               AS_HELP_STRING([--enable-debug],
                              [Enable debug (default is YES)]),
               [ac_cv_use_debug=$enableval],
               [ac_cv_use_debug=yes])
AC_CACHE_CHECK([whether to have verbose debug],
               [ac_cv_use_debug],
               [ac_cv_use_debug=yes])
if test x"$ac_cv_use_debug" = x"yes"; then
    AC_DEFINE(HIP_LOGFMT_LONG)
    AH_TEMPLATE(HIP_LOGFMT_LONG, [Defined to 1 if long log format output is enabled.])
    AC_DEFINE(CONFIG_HIP_DEBUG)
    AH_TEMPLATE(CONFIG_HIP_DEBUG, [Defined to 1 if debug output is enabled.])
fi

AC_ARG_ENABLE(midauth,
               AS_HELP_STRING([--enable-midauth],
                              [Enable middlebox authentification (default is NO)]),
               [ac_cv_use_midauth=$enableval],
               [ac_cv_use_midauth=no])
AC_CACHE_CHECK([whether to have middlebox authentification],
               [ac_cv_use_midauth],
               [ac_cv_use_midauth=no])
if test x"$ac_cv_use_midauth" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_MIDAUTH)
    AH_TEMPLATE(CONFIG_HIP_MIDAUTH,
                [Defined to 1 if midauth extension is enabled.])
fi
AM_CONDITIONAL(HIP_MIDAUTH, test x"$ac_cv_use_midauth" = x"yes")

AC_ARG_ENABLE(performance,
               AS_HELP_STRING([--enable-performance],
                              [Performace measurement support (default is NO)]),
               [ac_cv_use_performance=$enableval],
               [ac_cv_use_performance=no])
AC_CACHE_CHECK([whether to use performance measurement],
               [ac_cv_use_performance],
               [ac_cv_use_performance=no])
if test x"$ac_cv_use_performance" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_PERFORMANCE)
    AH_TEMPLATE(CONFIG_HIP_PERFORMANCE,
                [Defined to 1 if performance measurements are enabled.])
fi
AM_CONDITIONAL(HIP_PERFORMANCE, test x"$ac_cv_use_performance" = x"yes")

AC_ARG_ENABLE(demo,
               AS_HELP_STRING([--enable-demo],
                              [Demo output (default is NO)]),
               [ac_cv_use_demo=$enableval],
               [ac_cv_use_demo=no])
AC_CACHE_CHECK([whether to print output for demos],
               [ac_cv_use_demo],
               [ac_cv_use_demo=no])
if test x"$ac_cv_use_demo" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_DEMO)
    AH_TEMPLATE(CONFIG_HIP_DEMO, [Defined to 1 if demo is enabled.])
fi


# Parse modules directory
echo ""
echo "+-----------------------------------------------";
echo "| processing modules...";
echo "|";
$PYTHON ${srcdir}/process_modules.py -s ${srcdir} -d "${with_nomodules}"
if [[ "$?" != "0" ]]; then
    echo "configure: error: Module processing failed"
    exit 1
fi
echo "|";
echo "+-----------------------------------------------"
echo ""

AC_CONFIG_FILES([ Makefile doc/Doxyfile ])

AC_OUTPUT

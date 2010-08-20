ACLOCAL_AMFLAGS  = -I m4

HIPL_HEADER_LIST = $(wildcard $(addprefix $(srcdir)/,firewall/*.h hipd/*.h lib/*/*.h modules/*/*/*.h))

# For "make dist"
EXTRA_DIST =  .vimrc debian doc patches version.h
EXTRA_DIST += packaging process_modules.py tools/maintainer
EXTRA_DIST += $(wildcard modules/*/module_info.xml)
EXTRA_DIST += $(wildcard modules/*/Makefile.am) $(wildcard modules/*/*/*.c)
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/test/,*.pl *.sh))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/tools/,*.cfg *.pl *.sh))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/firewall/,*.cfg))
EXTRA_DIST += $(HIPL_HEADER_LIST)


### user programs ###
bin_PROGRAMS = test/auth_performance    \
               test/certteststub        \
               test/hc_performance

if HIP_PERFORMANCE
bin_PROGRAMS += test/dh_performance
endif


### superuser programs ###
sbin_PROGRAMS = hipd/hipd      \
                tools/hipconf  \
                tools/pisacert

if HIP_FIREWALL
sbin_PROGRAMS += firewall/hipfw
endif


### libraries ###
lib_LTLIBRARIES = lib/core/libhipcore.la
lib_LTLIBRARIES += lib/modularization/libmod.la


### source declarations ###

test_auth_performance_SOURCES = test/auth_performance.c
test_certteststub_SOURCES     = test/certteststub.c
test_dh_performance_SOURCES   = test/dh_performance.c
test_hc_performance_SOURCES   = test/hc_performance.c

tools_hipconf_SOURCES  = tools/hipconf.c
tools_pisacert_SOURCES = tools/pisacert.c

hipd_hipd_SOURCES = hipd/accessor.c              \
                    hipd/cert.c                  \
                    hipd/close.c                 \
                    hipd/configfilereader.c      \
                    hipd/cookie.c                \
                    hipd/dh.c                    \
                    hipd/esp_prot_anchordb.c     \
                    hipd/esp_prot_hipd_msg.c     \
                    hipd/esp_prot_light_update.c \
                    hipd/hadb.c                  \
                    hipd/hadb_legacy.c           \
                    hipd/hidb.c                  \
                    hipd/hip_socket.c            \
                    hipd/hipd.c                  \
                    hipd/hiprelay.c              \
                    hipd/hit_to_ip.c             \
                    hipd/init.c                  \
                    hipd/input.c                 \
                    hipd/keymat.c                \
                    hipd/maintenance.c           \
                    hipd/nat.c                   \
                    hipd/netdev.c                \
                    hipd/nsupdate.c              \
                    hipd/output.c                \
                    hipd/pkt_handling.c          \
                    hipd/registration.c          \
                    hipd/user.c                  \
                    hipd/user_ipsec_hipd_msg.c   \
                    hipd/user_ipsec_sadb_api.c

if HIP_MIDAUTH
hipd_hipd_SOURCES +=  hipd/pisa.c
endif

if HIP_OPPORTUNISTIC
hipd_hipd_SOURCES += hipd/oppdb.c                \
                     hipd/oppipdb.c
endif

firewall_hipfw_SOURCES = firewall/cache.c               \
                         firewall/cache_port.c          \
                         firewall/conntrack.c           \
                         firewall/dlist.c               \
                         firewall/esp_prot_api.c        \
                         firewall/esp_prot_config.c     \
                         firewall/esp_prot_conntrack.c  \
                         firewall/esp_prot_fw_msg.c     \
                         firewall/firewall.c            \
                         firewall/firewall_control.c    \
                         firewall/helpers.c             \
                         firewall/hslist.c              \
                         firewall/lsi.c                 \
                         firewall/reinject.c            \
                         firewall/rule_management.c     \
                         firewall/sysopp.c              \
                         firewall/user_ipsec_api.c      \
                         firewall/user_ipsec_esp.c      \
                         firewall/user_ipsec_fw_msg.c   \
                         firewall/user_ipsec_sadb.c

if HIP_MIDAUTH
firewall_hipfw_SOURCES += firewall/midauth.c   \
                          firewall/pisa.c      \
                          firewall/pisa_cert.c
endif


# TODO: libhipcore, libhipconf and libhiptool have circular
# dependencies. This needs to be addressed at some point.
lib_core_libhipcore_la_SOURCES = lib/core/builder.c         \
                                 lib/core/capability.c      \
                                 lib/core/certtools.c       \
                                 lib/core/conf.c            \
                                 lib/core/crypto.c          \
                                 lib/core/debug.c           \
                                 lib/core/esp_prot_common.c \
                                 lib/core/filemanip.c       \
                                 lib/core/hashchain.c       \
                                 lib/core/hashchain_store.c \
                                 lib/core/hashtable.c       \
                                 lib/core/hashtree.c        \
                                 lib/core/hip_udp.c         \
                                 lib/core/hit.c             \
                                 lib/core/hostid.c          \
                                 lib/core/hostsfiles.c      \
                                 lib/core/keylen.c          \
                                 lib/core/linkedlist.c      \
                                 lib/core/message.c         \
                                 lib/core/prefix.c          \
                                 lib/core/solve.c           \
                                 lib/core/statistics.c      \
                                 lib/core/straddr.c         \
                                 lib/core/transform.c       \
                                 lib/tool/checksum.c        \
                                 lib/tool/lutil.c           \
                                 lib/tool/nlink.c           \
                                 lib/tool/pk.c              \
                                 lib/tool/xfrmapi.c

if HIP_PERFORMANCE
lib_core_libhipcore_la_SOURCES += lib/core/performance.c
endif

lib_modularization_libmod_la_SOURCES = lib/modularization/lmod.c

# Initialize LDADD lists empty, because modules might add entries to LDADD. The
# module LDADDs need to be included before the standard LDADDs, because modules
# can depend on the core code.
hipd_hipd_LDADD      =
firewall_hipfw_LDADD =
tools_hipconf_LDADD  =

# Include module Makefile.am's.
# TODO: Make this inclusion dynamic
include modules/heartbeat/Makefile.am
include modules/heartbeat_update/Makefile.am
include modules/update/Makefile.am

### library dependencies ###

firewall_hipfw_LDADD          += lib/core/libhipcore.la
hipd_hipd_LDADD               += lib/modularization/libmod.la \
                                 lib/core/libhipcore.la
test_auth_performance_LDADD    = lib/core/libhipcore.la
test_certteststub_LDADD        = lib/core/libhipcore.la
test_dh_performance_LDADD      = lib/core/libhipcore.la
test_hc_performance_LDADD      = lib/core/libhipcore.la
tools_hipconf_LDADD           += lib/core/libhipcore.la
tools_pisacert_LDADD           = lib/core/libhipcore.la

dist_sbin_SCRIPTS = tools/hipdnskeyparse/hipdnskeyparse \
                    tools/hipdnsproxy/hipdnsproxy       \
                    tools/nsupdate.pl

dns_PYTHON = tools/hipdnsproxy/DNS/__init__.py      \
             tools/hipdnsproxy/DNS/Base.py          \
             tools/hipdnsproxy/DNS/Class.py         \
             tools/hipdnsproxy/DNS/lazy.py          \
             tools/hipdnsproxy/DNS/Lib.py           \
             tools/hipdnsproxy/DNS/Opcode.py        \
             tools/hipdnsproxy/DNS/Serialization.py \
             tools/hipdnsproxy/DNS/Status.py        \
             tools/hipdnsproxy/DNS/Type.py          \
             tools/hipdnsproxy/DNS/win32dns.py

dnsdir = $(pyexecdir)/hipdnsproxy/DNS

tools_hipdnskeyparse_PYTHON = tools/hipdnskeyparse/myasn.py

tools_hipdnsproxy_PYTHON = tools/hipdnsproxy/hosts.py       \
                           tools/hipdnsproxy/pyip6.py       \
                           tools/hipdnsproxy/util.py

tools_hipdnskeyparsedir = $(pyexecdir)
tools_hipdnsproxydir    = $(pyexecdir)


### misc stuff ###
doxygen: doc/Doxyfile
	doxygen $<

# CentOS 5.5 requires this or otherwise autoreconf gives the error:
# Makefile.am:213: `nodist_doc_DATA' is used but `docdir' is undefined
docdir = ${datadir}/doc/${PACKAGE} 

if HAVE_XMLTO
nodist_doc_DATA = doc/HOWTO.html doc/HOWTO.txt $(wildcard $(addprefix $(srcdir)/doc/,*.png))
endif

doc/HOWTO.html:  doc/HOWTO.xml
	xmlto -o $(@D) html-nochunks $<

doc/HOWTO.txt: doc/HOWTO.xml
	xmlto -o $(@D) txt $<

CLEANFILES = doc/HOWTO.html doc/HOWTO.txt
clean-local:
	rm -rf doc/doxy

bin deb increl rpm syncrepo:
	env PYEXECDIR=$(pyexecdir) @srcdir@/packaging/create-package.sh $@

autotools-clean: maintainer-clean
	rm -f aclocal.m4 compile config.* configure depcomp install-sh
	rm -f ltmain.sh m4/*.m4 Makefile.in missing py-compile

HIPL_HEADER_OBJS     = $(subst $(srcdir),$(builddir),$(HIPL_HEADER_LIST:.h=.ho))
CLEANFILES          += $(HIPL_HEADER_OBJS)
DISTCLEANFILES       = $(wildcard modules/*.h)

checkheaders: $(HIPL_HEADER_OBJS)
vpath %.h $(srcdir)
%.ho: %.h
	$(CC) -I$(srcdir) -I$(builddir) $(AM_CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

# Ensure that version.h is created before everything else. This does not work
# when creating specific objects that may depend on version.h directly.
BUILT_SOURCES = version.h
$(srcdir)/version.h: $(wildcard $(srcdir)/.bzr/branch/last-revision)
	bzr version-info $(srcdir) --custom --template='#define BZR_REVISION "{revno}"\n#define BZR_DATE "{date}"\n#define BZR_BRANCH "{branch_nick}"\n' > $@


# The complete doc/ subdirectory is in EXTRA_DIST, so files that should
# not be distributed need to be deleted manually from the distribution.
dist-hook:
	rm -f $(distdir)/doc/Doxyfile

.PHONY: bin checkheaders deb doxygen increl rpm syncrepo

# Copyright (c) 2010 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

ACLOCAL_AMFLAGS  = -I m4

HIPL_HEADER_LOCATIONS = firewall/*.h hipd/*.h lib/*/*.h modules/*/*/*.h test/*/*.h test/*/*/*.h
HIPL_HEADER_LIST = $(wildcard $(addprefix $(srcdir)/,$(HIPL_HEADER_LOCATIONS)))

# For "make dist"
EXTRA_DIST =  .vimrc debian doc patches version.h .uncrustify.cfg
EXTRA_DIST += .uncrustify-0.57.cfg tools/bazaar/plugins/stylecheck.py
EXTRA_DIST += packaging process_modules.py tools/maintainer
EXTRA_DIST += $(wildcard modules/*/module_info.xml)
EXTRA_DIST += $(wildcard modules/*/Makefile.am) $(wildcard modules/*/*/*.c)
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/tools/,*.cfg *.pl *.sh *.xml))
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


### test programs ###
noinst_PROGRAMS = test/fw_port_bindings_performance



### libraries ###
lib_LTLIBRARIES = lib/core/libhipcore.la


### tests ###
if HIP_UNITTESTS
TESTS           = test/check_firewall \
                  test/check_lib_core
check_PROGRAMS  = test/check_firewall \
                  test/check_lib_core
endif


### source declarations ###

test_auth_performance_SOURCES               = test/auth_performance.c
test_certteststub_SOURCES                   = test/certteststub.c
test_dh_performance_SOURCES                 = test/dh_performance.c
test_fw_port_bindings_performance_SOURCES   = test/fw_port_bindings_performance.c \
                                              firewall/file_buffer.c              \
                                              firewall/line_parser.c              \
                                              firewall/port_bindings.c
test_hc_performance_SOURCES                 = test/hc_performance.c

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
hipd_hipd_SOURCES += hipd/opp_mode.c
endif

firewall_hipfw_SOURCES = firewall/cache.c               \
                         firewall/conntrack.c           \
                         firewall/dlist.c               \
                         firewall/esp_prot_api.c        \
                         firewall/esp_prot_config.c     \
                         firewall/esp_prot_conntrack.c  \
                         firewall/esp_prot_fw_msg.c     \
                         firewall/file_buffer.c         \
                         firewall/firewall.c            \
                         firewall/firewall_control.c    \
                         firewall/helpers.c             \
                         firewall/hslist.c              \
                         firewall/line_parser.c         \
                         firewall/lsi.c                 \
                         firewall/main.c                \
                         firewall/port_bindings.c       \
                         firewall/reinject.c            \
                         firewall/rule_management.c     \
                         firewall/user_ipsec_api.c      \
                         firewall/user_ipsec_esp.c      \
                         firewall/user_ipsec_fw_msg.c   \
                         firewall/user_ipsec_sadb.c

if HIP_MIDAUTH
firewall_hipfw_SOURCES += firewall/midauth.c   \
                          firewall/pisa.c      \
                          firewall/pisa_cert.c
endif


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
                                 lib/core/modularization.c  \
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


test_check_firewall_SOURCES = test/check_firewall.c         \
                              test/firewall/file_buffer.c   \
                              test/firewall/line_parser.c   \
                              test/firewall/port_bindings.c \
                              test/firewall/conntrack.c     \
                              firewall/cache.c              \
                              firewall/dlist.c              \
                              firewall/esp_prot_api.c       \
                              firewall/esp_prot_config.c    \
                              firewall/esp_prot_conntrack.c \
                              firewall/esp_prot_fw_msg.c    \
                              firewall/firewall.c           \
                              firewall/firewall_control.c   \
                              firewall/helpers.c            \
                              firewall/hslist.c             \
                              firewall/lsi.c                \
                              firewall/reinject.c           \
                              firewall/rule_management.c    \
                              firewall/user_ipsec_api.c     \
                              firewall/user_ipsec_esp.c     \
                              firewall/user_ipsec_fw_msg.c  \
                              firewall/user_ipsec_sadb.c

test_check_lib_core_SOURCES = test/check_lib_core.c          \
                              test/lib/core/hit.c            \
                              test/lib/core/straddr.c

# Include module Makefile.am's.
# TODO: Make this inclusion dynamic
include modules/heartbeat/Makefile.am
include modules/heartbeat_update/Makefile.am
include modules/update/Makefile.am

### library dependencies ###

firewall_hipfw_LDADD                     = lib/core/libhipcore.la
hipd_hipd_LDADD                          = lib/core/libhipcore.la
test_auth_performance_LDADD              = lib/core/libhipcore.la
test_check_firewall_LDADD                = lib/core/libhipcore.la
test_check_lib_core_LDADD                = lib/core/libhipcore.la
test_certteststub_LDADD                  = lib/core/libhipcore.la
test_dh_performance_LDADD                = lib/core/libhipcore.la
test_fw_port_bindings_performance_LDADD  = lib/core/libhipcore.la
test_hc_performance_LDADD                = lib/core/libhipcore.la
tools_hipconf_LDADD                      = lib/core/libhipcore.la
tools_pisacert_LDADD                     = lib/core/libhipcore.la

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

dnsdir = $(pythondir)/DNS

tools_hipdnskeyparse_PYTHON = tools/hipdnskeyparse/myasn.py

tools_hipdnsproxy_PYTHON = tools/hipdnsproxy/hosts.py       \
                           tools/hipdnsproxy/pyip6.py       \
                           tools/hipdnsproxy/util.py

tools_hipdnskeyparsedir = $(pythondir)/hipdnskeyparse
tools_hipdnsproxydir    = $(pythondir)/hipdnsproxy


### misc stuff ###

# This is supposed to be a sanity check target to run before pushing changes
# to the world at large. It should catch a number of easily-avoidable mistakes.
alltests: doxygen checkheaders check distcheck

doxygen: doc/Doxyfile
	doxygen $<

if HAVE_XMLTO
nodist_doc_DATA = doc/HOWTO.html doc/HOWTO.txt $(wildcard $(addprefix $(srcdir)/doc/,*.png))
endif

doc/HOWTO.html:  doc/HOWTO.xml
	xmlto -o $(@D) html-nochunks $<

doc/HOWTO.txt: doc/HOWTO.xml
	xmlto -o $(@D) txt $<

CLEANFILES = doc/HOWTO.html doc/HOWTO.txt
clean-local:
	rm -rf doc/doxy rpmbuild

bin deb rpm syncrepo syncrepo_deb syncrepo_rpm: $(srcdir)/version.h
	@srcdir@/packaging/create-package.sh $@

autotools-clean: maintainer-clean
	rm -f aclocal.m4 compile config.* configure depcomp install-sh
	rm -f ltmain.sh m4/*.m4 Makefile.in missing py-compile

HIPL_HEADER_OBJS     = $(subst $(srcdir),$(builddir),$(HIPL_HEADER_LIST:.h=.ho))
CLEANFILES          += $(HIPL_HEADER_OBJS)
DISTCLEANFILES       = $(wildcard modules/*.h)

$(HIPL_HEADER_OBJS): $(BUILT_SOURCES)
checkheaders: $(HIPL_HEADER_OBJS)
vpath %.h $(srcdir)
%.ho: %.h
	$(AM_V_CC) $(CC) -I$(srcdir) -I$(builddir) $(AM_CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

# Ensure that version.h is created before everything else. This does not work
# when creating specific objects that may depend on version.h directly.
BUILT_SOURCES = version.h
$(srcdir)/version.h: $(wildcard $(srcdir)/.bzr/checkout/dirstate)
	bzr version-info $(srcdir) --custom --template='#define VCS_REVISION "{revno}"\n#define VCS_DATE "{date}"\n#define VCS_BRANCH "{branch_nick}"\n' > $@


# Files that are generated by configure should not be distributed.
dist-hook:
	rm -f $(addprefix $(distdir)/doc/,Doxyfile HOWTO.xml)
	rm -f $(addprefix $(distdir)/tools/,nsupdate.pl hipdnsproxy/hipdnsproxy hipdnskeyparse/hipdnskeyparse)
	rm -f $(addprefix $(distdir)/debian/,hipl-dnsproxy.dirs hipl-dnsproxy.install)

.PHONY: alltests bin checkheaders deb doxygen rpm syncrepo*

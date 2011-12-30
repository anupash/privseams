# Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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

HIPL_HEADER_LOCATIONS = firewall/*.h hipd/*.h lib/*/*.h modules/*/*/*.h test/*.h test/*/*.h test/*/*/*.h
HIPL_HEADER_LIST = $(wildcard $(addprefix $(srcdir)/,$(HIPL_HEADER_LOCATIONS)))

# For "make dist"
EXTRA_DIST  = .dir-locals.el .uncrustify.cfg .uncrustify-0.57.cfg .vimrc
EXTRA_DIST += process_modules.py version.h
EXTRA_DIST += debian doc patches packaging tools/bazaar tools/maintainer
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
                tools/pisacert \
                tools/accert

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
                  test/check_lib_core \
                  test/check_lib_tool \
                  test/check_modules_midauth
check_PROGRAMS  = test/check_firewall \
                  test/check_lib_core \
                  test/check_lib_tool \
                  test/check_modules_midauth
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
tools_accert_SOURCES = tools/accert.c

hipd_hipd_sources = hipd/accessor.c              \
                    hipd/cert.c                  \
                    hipd/close.c                 \
                    hipd/configfilereader.c      \
                    hipd/cookie.c                \
                    hipd/dh.c                    \
                    hipd/esp_prot_anchordb.c     \
                    hipd/esp_prot_hipd_msg.c     \
                    hipd/esp_prot_light_update.c \
                    hipd/hadb.c                  \
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
                    hipd/opp_mode.c              \
                    hipd/output.c                \
                    hipd/pkt_handling.c          \
                    hipd/registration.c          \
                    hipd/user.c                  \
                    hipd/user_ipsec_hipd_msg.c   \
                    hipd/user_ipsec_sadb_api.c   \
                    modules/heartbeat/hipd/heartbeat.c          \
                    modules/heartbeat_update/hipd/hb_update.c   \
                    modules/midauth/lib/midauth_builder.c       \
                    modules/update/hipd/update.c                \
                    modules/update/hipd/update_builder.c        \
                    modules/update/hipd/update_locator.c        \
                    modules/update/hipd/update_param_handling.c \
                    modules/signaling/hipd/signaling.c \
                    modules/signaling/hipd/signaling_hipd_msg.c \
                    modules/signaling/hipd/signaling_hipd_state.c \
                    modules/signaling/hipd/signaling_hipd_user_msg.c

if HIP_MIDAUTH
hipd_hipd_sources += hipd/pisa.c
endif

hipd_hipd_SOURCES = $(hipd_hipd_sources)                \
                    modules/midauth/hipd/midauth.c      \
                    hipd/main.c

firewall_hipfw_sources = firewall/cache.c               \
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
                         firewall/port_bindings.c       \
                         firewall/reinject.c            \
                         firewall/rule_management.c     \
                         firewall/user_ipsec_api.c      \
                         firewall/user_ipsec_esp.c      \
                         firewall/user_ipsec_fw_msg.c   \
                         firewall/user_ipsec_sadb.c     \
                         modules/midauth/lib/midauth_builder.c \
                         modules/signaling/firewall/signaling_hipfw.c \
                         modules/signaling/firewall/signaling_cdb.c \
                         modules/signaling/firewall/signaling_hipfw_oslayer.c \
                         modules/signaling/firewall/signaling_hipfw_user_msg.c \
                         modules/signaling/firewall/signaling_policy_engine.c \
                         modules/signaling/firewall/signaling_hipfw_feedback.c

if HIP_MIDAUTH
firewall_hipfw_sources += firewall/midauth.c   \
                          firewall/pisa.c      \
                          firewall/pisa_cert.c
endif

# The firewall unit test program is linked against the firewall object files.
# To avoid duplicate symbols during linking some object files need to excluded.
# Add all files that need to be excluded here.
firewall_hipfw_SOURCES = $(firewall_hipfw_sources) \
                         firewall/conntrack.c      \
                         firewall/main.c

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
                                 lib/tool/nlink.c           \
                                 lib/tool/pk.c              \
                                 lib/tool/xfrmapi.c         \
                                 modules/signaling/lib/signaling_common_builder.c \
                                 modules/signaling/lib/signaling_prot_common.c \
                                 modules/signaling/lib/signaling_oslayer.c \
                                 modules/signaling/lib/signaling_user_api.c \
                                 modules/signaling/lib/signaling_user_management.c \
                                 modules/signaling/lib/signaling_x509_api.c


if HIP_PERFORMANCE
lib_core_libhipcore_la_SOURCES += lib/core/performance.c
endif


test_check_firewall_SOURCES = test/check_firewall.c          \
                              test/mocks.c                   \
                              test/firewall/conntrack.c      \
                              test/firewall/file_buffer.c    \
                              test/firewall/helpers.c        \
                              test/firewall/line_parser.c    \
                              test/firewall/port_bindings.c  \
                              $(firewall_hipfw_sources)

test_check_lib_core_SOURCES = test/check_lib_core.c          \
                              test/lib/core/crypto.c         \
                              test/lib/core/hit.c            \
                              test/lib/core/hostid.c         \
                              test/lib/core/solve.c          \
                              test/lib/core/straddr.c

test_check_lib_tool_SOURCES = test/check_lib_tool.c          \
                              test/lib/tool/checksum.c       \
                              test/lib/tool/pk.c

test_check_modules_midauth_SOURCES = test/check_modules_midauth.c               \
                                     test/modules/midauth/lib/midauth_builder.c \
                                     test/modules/midauth/hipd/midauth.c        \
                                     $(hipd_hipd_sources)


### static library dependencies ###

firewall_hipfw_LDADD                     = lib/core/libhipcore.la
firewall_hipfw_LDADD                    +=-L/home/ashish/Thesis/x509ac -lx509ac -lssl
hipd_hipd_LDADD                          = lib/core/libhipcore.la
hipd_hipd_LDADD                         +=-L/home/ashish/Thesis/x509ac -lx509ac -lssl
test_auth_performance_LDADD              = lib/core/libhipcore.la
test_check_firewall_LDADD                = lib/core/libhipcore.la
test_check_lib_core_LDADD                = lib/core/libhipcore.la
test_check_lib_tool_LDADD                = lib/core/libhipcore.la
test_check_modules_midauth_LDADD         = lib/core/libhipcore.la
test_certteststub_LDADD                  = lib/core/libhipcore.la
test_dh_performance_LDADD                = lib/core/libhipcore.la
test_fw_port_bindings_performance_LDADD  = lib/core/libhipcore.la
test_hc_performance_LDADD                = lib/core/libhipcore.la
tools_hipconf_LDADD                      = lib/core/libhipcore.la
tools_pisacert_LDADD                     = lib/core/libhipcore.la
tools_accert_LDADD                       = lib/core/libhipcore.la
tools_accert_LDADD                      += -L/home/ashish/Thesis/x509ac -lx509ac

### dynamic library dependencies ###

test_check_firewall_LDFLAGS              = -ldl

#include modules/signaling/Makefile.am

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

BUILT_SOURCES = version.h
$(srcdir)/version.h: $(wildcard $(srcdir)/.bzr/checkout/dirstate)
	bzr version-info $(srcdir) --custom --template='#define VCS_REVISION "{revno}"\n#define VCS_DATE "{date}"\n#define VCS_BRANCH "{branch_nick}"\n' > $@


# Files that are generated by configure should not be distributed.
dist-hook:
	rm -f $(addprefix $(distdir)/doc/,Doxyfile HOWTO.xml)
	rm -f $(addprefix $(distdir)/tools/,nsupdate.pl hipdnsproxy/hipdnsproxy hipdnskeyparse/hipdnskeyparse)
	rm -f $(addprefix $(distdir)/debian/,hipl-dnsproxy.dirs hipl-dnsproxy.install)
	rm -f $(distdir)/packaging/openwrt/hipl/Makefile

.PHONY: alltests bin checkheaders deb doxygen rpm syncrepo*

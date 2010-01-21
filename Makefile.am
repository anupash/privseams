ACLOCAL_AMFLAGS  = -I m4

# For "make dist"
#
# XX FIX: use dist_doc_DATA for all documentation (if you change this,
# make sure the check the "make bin" still works)
#
EXTRA_DIST =  doc/COPYING doc/HACKING doc/HOWTO.xml doc/drafts doc/Makefile
EXTRA_DIST += doc/README doc/design_choices.bib test/configs patches
EXTRA_DIST += doc/base-exchange-relay.png doc/base-exchange-rvs.png
EXTRA_DIST += hipsock jip
EXTRA_DIST += test/packaging/create-package.sh
EXTRA_DIST += test/packaging/hipl-rpm.spec test/packaging/hipl-deb.spec 
EXTRA_DIST += test/packaging/debbuild
EXTRA_DIST += test/packaging/rh-init.d-hipd test/packaging/rh-init.d-hipfw test/packaging/rh-init.d-dnsproxy
EXTRA_DIST += test/packaging/debian-init.d-hipd test/packaging/debian-init.d-hipfw test/packaging/debian-init.d-dnsproxy
# The design choices doc is currently depracated
EXTRA_DIST += doc/design_choices.tex doc/hipl.tex doc/acronyms.tex
EXTRA_DIST += doc/design_choices_macros.tex doc/catalogue.tex doc/fig
EXTRA_DIST += doc/doxygen.h doc/Doxyfile
EXTRA_DIST += hipext/hipext.xpi hipext/src/content/hipext.xul hipext/src/content/hipext.js hipext/src/chrome.manifest
EXTRA_DIST += hipext/src/install.rdf hipext/src/config_build.sh hipext/src/build.sh hipext/hipext.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += autogen.sh
EXTRA_DIST += $(wildcard lib/android/*.{c,h})
EXTRA_DIST += $(wildcard lib/conf/*.h)
EXTRA_DIST += $(wildcard lib/core/*.h)
EXTRA_DIST += $(wildcard lib/gui/*.h)
EXTRA_DIST += $(wildcard lib/ipsec/*.h)
EXTRA_DIST += $(wildcard lib/opphip/*.h)
EXTRA_DIST += $(wildcard lib/performance/*.h)
EXTRA_DIST += $(wildcard lib/tool/*.h)
EXTRA_DIST += $(wildcard hipd/*.h)
EXTRA_DIST += $(wildcard firewall/*.h)
EXTRA_DIST += $(wildcard test/*.h)
EXTRA_DIST += tools/gen-python-starter.sh \
              $(wildcard tools/*.h)

# XX TODO: remove these when maemo building uses spec files
EXTRA_DIST += test/packaging/create-deb.sh
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/control
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/prerm
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/rules
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/control-src
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/preinst
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/control
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/prerm
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/rules
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/control-src
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/preinst
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/control
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN/control
EXTRA_DIST += test/packaging/armel/DEBIAN/prerm
EXTRA_DIST += test/packaging/armel/DEBIAN/rules
EXTRA_DIST += test/packaging/armel/DEBIAN/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN/control-src
EXTRA_DIST += test/packaging/armel/DEBIAN/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN/preinst
EXTRA_DIST += libinet6/include

### bin_PROGRAMS ###
bin_PROGRAMS = test/certteststub \
               test/hc_performance \
               test/auth_performance

if HIP_PERFORMANCE
bin_PROGRAMS += test/dh_performance
endif

### sbin_PROGRAMS ###
sbin_PROGRAMS = hipd/hipd \
                tools/hipconf \
                tools/pisacert

if HIP_FIREWALL
sbin_PROGRAMS += firewall/hipfw
endif

### lib_LTLIBRARIES ###
lib_LTLIBRARIES = lib/conf/libhipconf.la \
                  lib/core/libhipcore.la \
                  lib/tool/libhiptool.la
if HIP_PFKEY
lib_LTLIBRARIES += lib/ipsec/libhipsec.la
endif

if HIP_PERFORMANCE
lib_LTLIBRARIES += lib/performance/libperformance.la
endif

if HIP_OPPORTUNISTIC
lib_LTLIBRARIES += lib/opphip/libopphip.la
endif

### *_SOURCES ###
test_certteststub_SOURCES = test/certteststub.c

test_hc_performance_SOURCES = test/hc_performance.c

test_auth_performance_SOURCES = test/auth_performance.c

if HIP_PERFORMANCE
test_dh_performance_SOURCES = test/dh_performance.c
endif

tools_hipconf_SOURCES = tools/hipconftool.c

tools_pisacert_SOURCES = tools/pisacert.c

hipd_hipd_SOURCES = hipd/update.c \
                    hipd/hipd.c \
                    hipd/keymat.c \
                    hipd/blind.c \
                    hipd/hiprelay.c \
                    hipd/registration.c \
                    hipd/user.c \
                    hipd/hadb.c \
                    hipd/oppdb.c \
                    hipd/close.c \
                    hipd/configfilereader.c \
                    hipd/input.c \
                    hipd/output.c \
                    hipd/hidb.c \
                    hipd/cookie.c \
                    hipd/netdev.c \
                    hipd/bos.c \
                    hipd/nat.c \
                    hipd/icookie.c \
                    hipd/init.c \
                    hipd/maintenance.c \
                    hipd/accessor.c \
                    hipd/oppipdb.c \
                    hipd/dh.c \
                    hipd/tcptimeout.c \
                    hipd/cert.c \
                    hipd/user_ipsec_sadb_api.c \
                    hipd/user_ipsec_hipd_msg.c \
                    hipd/esp_prot_hipd_msg.c \
                    hipd/esp_prot_anchordb.c \
                    hipd/esp_prot_light_update.c \
                    hipd/nsupdate.c \
                    hipd/hit_to_ip.c \
                    hipd/update_legacy.c \
                    hipd/hadb_legacy.c \
                    hipd/heartbeat.c 

if HIP_PFKEY
hipd_hipd_SOURCES += hipd/pfkeyapi.c
endif

if HIP_MIDAUTH
hipd_hipd_SOURCES +=  hipd/pisa.c
endif

if HIP_FIREWALL
firewall_hipfw_SOURCES = firewall/firewall.c \
                         firewall/conntrack.c \
                         firewall/rule_management.c \
                         firewall/helpers.c \
                         firewall/firewall_control.c \
                         firewall/proxydb.c \
                         firewall/conndb.c \
                         firewall/dlist.c \
                         firewall/hslist.c \
                         firewall/user_ipsec_api.c \
                         firewall/user_ipsec_esp.c \
                         firewall/user_ipsec_sadb.c \
                         firewall/user_ipsec_fw_msg.c \
                         firewall/common_hipd_msg.c \
                         firewall/esp_prot_api.c \
                         firewall/esp_prot_fw_msg.c \
                         firewall/esp_prot_conntrack.c \
                         firewall/esp_prot_config.c \
                         firewall/proxy.c \
                         firewall/opptcp.c \
                         firewall/firewalldb.c \
                         firewall/lsi.c \
                         firewall/sysopp.c \
                         firewall/sava_api.c \
                         firewall/savah_gateway.c \
                         firewall/cache.c \
                         firewall/cache_port.c \
                         firewall/datapkt.c

if HIP_MIDAUTH
firewall_hipfw_SOURCES += firewall/midauth.c \
                          firewall/pisa.c \
                          firewall/pisa_cert.c
endif
endif # HIP_FIREWALL

lib_conf_libhipconf_la_SOURCES = lib/conf/hipconf.c

lib_core_libhipcore_la_SOURCES = lib/core/builder.c \
                                 lib/core/hashtable.c \
                                 lib/core/hashtree.c \
                                 lib/core/utils.c \
                                 lib/core/certtools.c \
                                 lib/core/linkedlist.c \
                                 lib/core/debug.c \
                                 lib/core/message.c \
                                 lib/core/esp_prot_common.c \
                                 lib/core/misc.c \
                                 lib/core/hashchain.c \
                                 lib/core/hashchain_store.c \
                                 lib/core/hip_statistics.c \
                                 lib/core/getendpointinfo.c

if HIP_PRIVSEP
lib_core_libhipcore_la_SOURCES += lib/core/hip_capability.c
endif

lib_tool_libhiptool_la_SOURCES = lib/tool/crypto.c \
                                 lib/tool/pk.c \
                                 lib/tool/nlink.c \
                                 lib/tool/lutil.c

if HIP_PFKEY
############################ NOTE ##################################
#
# Note: when you upgrade this library, please do the following:
#
# 1. uncomment policy_parse.y and policy_token.l lines
# 2. "make"
# 3. disable the policy_parse.y and policy_token.l lines again
# 4. commit the code (including lex/yacc generated c files)
#
# I could not make the lex/yacc stuff work with "make dist" which
# is mandatory for building e.g. rpm packages. -mk
####################################################################
lib_ipsec_libhipsec_la_SOURCES = lib/ipsec/ipsec_strerror.c \
                                 lib/ipsec/pfkey.c \
                                #lib/ipsec/policy_parse.y \
                                #lib/ipsec/policy_token.l

AM_YFLAGS = -d -p __libhipsec
AM_LFLAGS = -P__libhipsec -olex.yy.c

BUILT_SOURCES = lib/ipsec/policy_parse.h

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
#lib_ipsec_la_LDFLAGS = -version-info 0:1:0
#lib_ipsec_la_LIBADD = $(LEXLIB)

#DISTCLEANFILES = policy_parse.c policy_token.c policy_token.h
DISTCLEANFILES = lib/ipsec/policy_token.h

else

# don't use libipsec, but xfrmapi
lib_tool_libhiptool_la_SOURCES += lib/tool/xfrmapi.c

endif # HIPPFKEY

if HIP_PERFORMANCE
lib_performance_libperformance_la_SOURCES = lib/performance/performance.c
endif

if HIP_OPPORTUNISTIC
lib_opphip_libopphip_la_SOURCES  = lib/opphip/wrap.c \
                                   lib/opphip/wrap_db.c
endif

### *_LDADD ###
test_certteststub_LDADD = lib/core/libhipcore.la \
                          lib/tool/libhiptool.la
if HIP_PERFORMANCE
test_certteststub_LDADD += lib/performance/libperformance.la
endif

test_hc_performance_LDADD = lib/core/libhipcore.la \
                            lib/tool/libhiptool.la

if HIP_PERFORMANCE
test_hc_performance_LDADD += lib/performance/libperformance.la
endif

test_auth_performance_LDADD = lib/core/libhipcore.la \
                              lib/tool/libhiptool.la

if HIP_PERFORMANCE
test_auth_performance_LDADD += lib/performance/libperformance.la
endif

if HIP_PERFORMANCE
test_dh_performance_LDADD = lib/core/libhipcore.la \
                            lib/tool/libhiptool.la \
                            lib/performance/libperformance.la
endif

tools_hipconf_LDADD = lib/core/libhipcore.la \
                      lib/tool/libhiptool.la \
                      lib/conf/libhipconf.la

# required by libhipconf
if HIP_PERFORMANCE
tools_hipconf_LDADD += lib/performance/libperformance.la
endif

tools_pisacert_LDADD = lib/core/libhipcore.la \
                       lib/tool/libhiptool.la

if HIP_PERFORMANCE
tools_pisacert_LDADD += lib/performance/libperformance.la
endif

hipd_hipd_LDADD = lib/core/libhipcore.la \
                  lib/conf/libhipconf.la \
                  lib/tool/libhiptool.la

if HIP_PERFORMANCE
hipd_hipd_LDADD += lib/performance/libperformance.la
endif

if HIP_PFKEY
hipd_hipd_LDADD += lib/ipsec/libhipsec.la
endif

if HIP_FIREWALL
firewall_hipfw_LDADD = lib/core/libhipcore.la \
                       lib/tool/libhiptool.la

if HIP_PERFORMANCE
firewall_hipfw_LDADD += lib/performance/libperformance.la
endif

endif # HIP_FIREWALL

CLEANFILES = tools/hipdnsproxy tools/hipdnskeyparse
             
###### PYTHON stuff below ######
# TODO python parts still needs clean-up
if HAVE_PYTHON

# These two scripts are generated in the end to get the python paths correct.
# Currently, I don't know a better way to deal with the python code. -miika
dist_sbin_SCRIPTS = tools/hipdnsproxy \
                    tools/hipdnskeyparse \
                    tools/nsupdate.pl

dns_PYTHON = tools/DNS/Base.py \
             tools/DNS/Lib.py \
             tools/DNS/Type.py \
             tools/DNS/Class.py \
             tools/DNS/Opcode.py \
             tools/DNS/win32dns.py \
             tools/DNS/__init__.py \
             tools/DNS/pyip6.py \
             tools/DNS/lazy.py \
             tools/DNS/Status.py \
             tools/DNS/Serialization.py
             
dnsdir = $(pyexecdir)/tools/DNS

tools_hipdnsproxy_PYTHON = tools/dnsproxy.py \
                           tools/pyip6.py \
                           tools/hosts.py \
                           tools/util.py
                           
tools_hipdnsproxydir = $(pyexecdir)/tools/hipdnsproxy

tools_hipdnskeyparse_PYTHON = tools/parse-key-3.py \
                              tools/myasn.py
                              
tools_hipdnskeyparsedir = $(pyexecdir)/tools/hipdnskeyparse

endif # HAVE_PYTHON

# TODO directly stating targets seems wrong in Makefile.am - Rene
doxygen:
	cd doc && doxygen
rpm:
	test/packaging/create-package.sh rpm

olddeb:
	env PYEXECDIR=$(pyexecdir) test/packaging/create-deb.sh
	env PYEXECDIR=$(pyexecdir) test/packaging/create-deb.sh -s

deb:
	env PYEXECDIR=$(pyexecdir) test/packaging/create-package.sh deb

bin:
	env PYEXECDIR=$(pyexecdir) test/packaging/create-package.sh bin

increl:
	test/packaging/create-package.sh increl

syncrepo:
	test/packaging/create-package.sh syncrepo

# Automake does not build the shell scripts without this
tools/hipdnsproxy:
	@sh tools/gen-python-starter.sh $(pyexecdir)/tools/hipdnsproxy tools/dnsproxy.py tools/hipdnsproxy

tools/hipdnskeyparse:
	@sh tools/gen-python-starter.sh $(pyexecdir)/tools/hipdnskeyparse tools/parse-key-3.py tools/hipdnskeyparse

# This workaround forces automake to generate the scripts on each run. It is
# necessary because otherwise "make rpm" target has the old $pyexecdir from
# "make dist" and it refuses to build the scripts again.
all-local:
	@rm -f tools/hipdnsproxy
	@rm -f tools/hipdnskeyparse
	@sh tools/gen-python-starter.sh $(pyexecdir)/tools/hipdnsproxy tools/dnsproxy.py tools/hipdnsproxy
	@sh tools/gen-python-starter.sh $(pyexecdir)/tools/hipdnskeyparse tools/parse-key-3.py tools/hipdnskeyparse

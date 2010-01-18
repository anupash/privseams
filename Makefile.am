ACLOCAL_AMFLAGS  = -I m4

# For "make dist"
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
EXTRA_DIST += doc/HACKING
EXTRA_DIST += doc/doxygen.h doc/Doxyfile
EXTRA_DIST += hipext/hipext.xpi hipext/src/content/hipext.xul hipext/src/content/hipext.js hipext/src/chrome.manifest
EXTRA_DIST += hipext/src/install.rdf hipext/src/config_build.sh hipext/src/build.sh hipext/hipext.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += i3-cfg-PL.xml
EXTRA_DIST += autogen.sh
EXTRA_DIST += $(wildcard agent/*.h)
EXTRA_DIST += $(wildcard libdht/*.h)
EXTRA_DIST += $(wildcard libhipconf/*.h)
EXTRA_DIST += $(wildcard libhipcore/*.h)
EXTRA_DIST += $(wildcard libhipgui/*.h)
EXTRA_DIST += $(wildcard libhiptool/*.h)
EXTRA_DIST += $(wildcard libopphip/*.h)
EXTRA_DIST += $(wildcard performance/*.h)
EXTRA_DIST += $(wildcard libhipandroid/*.{c,h})
EXTRA_DIST += $(wildcard hipd/*.h)
EXTRA_DIST += $(wildcard firewall/*.h)
EXTRA_DIST += $(wildcard test/*.h)

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

# Default pkgdatadir is /usr/[local]/share/hipl/pixmaps/hipmanager.png.
# Gtk requires the images without the hipl prefix hence we use ".." below
imagesdir = $(pkgdatadir)/../pixmaps
dist_images_DATA = libhipgui/hipmanager.png

SUBDIRS =
sbin_PROGRAMS = 

if HIP_LIBINET6
SUBDIRS += libinet6
endif

### libhipcore ###
lib_LTLIBRARIES = libhipcore/libhipcore.la

libhipcore_libhipcore_la_SOURCES  = libhipcore/builder.c \
                                    libhipcore/hashtable.c \
                                    libhipcore/hashtree.c \
                                    libhipcore/utils.c \
                                    libhipcore/hashtree.c \
                                    libhipcore/certtools.c \
                                    libhipcore/linkedlist.c \
                                    libhipcore/debug.c \
                                    libhipcore/message.c \
                                    libhipcore/esp_prot_common.c \
                                    libhipcore/misc.c \
                                    libhipcore/hashchain.c \
                                    libhipcore/sqlitedbapi.c \
                                    libhipcore/hashchain_store.c \
                                    libhipcore/hip_statistics.c \
                                    libhipcore/getendpointinfo.c

if HIP_PRIVSEP
libhipcore_libhipcore_la_SOURCES += libhipcore/hip_capability.c
endif

### libhiptool ###
lib_LTLIBRARIES += libhiptool/libhiptool.la

libhiptool_libhiptool_la_SOURCES = libhiptool/crypto.c \
                                   libhiptool/pk.c \
                                   libhiptool/nlink.c \
                                   libhiptool/lutil.c

if HIP_PFKEY
else
libhiptool_libhiptool_la_SOURCES += libhiptool/xfrmapi.c
endif

if HIP_PERFORMANCE
lib_LTLIBRARIES += performance/libperformance.la
performance_libperformance_la_SOURCES = performance/performance.c
endif

lib_LTLIBRARIES += libhipconf/libhipconf.la

libhipconf_libhipconf_la_SOURCES = libhipconf/hipconf.c

if HIP_PFKEY
SUBDIRS += libipsec
endif

### libopphip ###
if HIP_OPPORTUNISTIC

lib_LTLIBRARIES += libopphip/libopphip.la

libopphip_libopphip_la_SOURCES  = libopphip/wrap.c \
                                  libopphip/wrap_db.c
endif

### libdht ###
if HIP_DHT

lib_LTLIBRARIES += libdht/libhipopendht.la

# NOTE: this would overwrite AM_CFLAGS, so we need to append it
libdht_libhipopendht_la_CFLAGS = `xml2-config --cflags` @AM_CFLAGS@

libdht_libhipopendht_la_SOURCES = libdht/libhipopendht.c \
                                  libdht/libhipopendhtxml.c
endif

if HIP_I3
SUBDIRS += i3
endif

### tools ###
bin_PROGRAMS = tools/hipconf \
               tools/pisacert

tools_hipconf_SOURCES = tools/hipconftool.c
tools_pisacert_SOURCES = tools/pisacert.c

tools_hipconf_LDADD = libhipcore/libhipcore.la \
                      libhiptool/libhiptool.la \
                      libhipconf/libhipconf.la

# required by libhipconf
if HIP_PERFORMANCE
tools_hipconf_LDADD += performance/libperformance.la
endif

if HIP_DHT
tools_hipconf_LDADD += libdht/libhipopendht.la
endif

tools_pisacert_LDADD = libhipcore/libhipcore.la \
                       libhiptool/libhiptool.la

if HIP_PERFORMANCE
tools_pisacert_LDADD += performance/libperformance.la
endif

### test ###
bin_PROGRAMS += test/conntest-client-opp \
                test/conntest-client-hip \
                test/conntest-client-native \
                test/conntest-client-native-user-key \
                test/conntest-server \
                test/conntest-server-native \
                test/hipsetup \
                test/first_test \
                test/cookietest \
                test/keygentest \
                test/hashtest \
                test/listtest \
                test/opendhtteststub \
                test/certteststub \
                test/sqliteteststub \
                test/hc_performance \
                test/auth_performance
               
if HIP_PERFORMANCE
bin_PROGRAMS += test/dh_performance
endif
test_conntest_client_opp_SOURCES = test/conntest-client-opp.c \
                                   test/conntest.c
test_conntest_client_opp_LDADD = libhipcore/libhipcore.la \
                                 libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_opp_LDADD += performance/libperformance.la
endif

test_conntest_client_hip_SOURCES = test/conntest-client-hip.c \
                                   test/conntest.c
test_conntest_client_hip_LDADD = libhipcore/libhipcore.la \
                                 libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_hip_LDADD += performance/libperformance.la
endif

test_conntest_client_native_SOURCES = test/conntest-client-native.c \
                                      test/conntest.c
test_conntest_client_native_LDADD = libhipcore/libhipcore.la \
                                    libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_native_LDADD += performance/libperformance.la
endif

test_conntest_client_native_user_key_SOURCES = test/conntest-client-native-user-key.c
test_conntest_client_native_user_key_LDADD = libhipcore/libhipcore.la \
                                             libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_native_user_key_LDADD += performance/libperformance.la
endif

test_conntest_server_SOURCES = test/conntest-server.c \
                               test/conntest.c
test_conntest_server_LDADD = libhipcore/libhipcore.la \
                             libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_server_LDADD += performance/libperformance.la
endif

test_conntest_server_native_SOURCES = test/conntest-server-native.c \
                                      test/conntest.c
test_conntest_server_native_LDADD = libhipcore/libhipcore.la \
                                    libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_server_native_LDADD += performance/libperformance.la
endif

test_hipsetup_SOURCES = test/hipsetup.c \
                        test/misc_install.c \
                        test/conntest.c
test_hipsetup_LDADD = libhipcore/libhipcore.la \
                      libhiptool/libhiptool.la \
                      libhipconf/libhipconf.la
if HIP_DHT
test_hipsetup_LDADD += libdht/libhipopendht.la
endif

if HIP_PERFORMANCE
test_hipsetup_LDADD += performance/libperformance.la
endif

test_first_test_SOURCES = test/first_test.c \
                          test/misc_install.c \
                          test/conntest.c
test_first_test_LDADD = libhipcore/libhipcore.la \
                        libhiptool/libhiptool.la \
                        libhipconf/libhipconf.la
if HIP_DHT
test_first_test_LDADD += libdht/libhipopendht.la
endif

if HIP_PERFORMANCE
test_first_test_LDADD += performance/libperformance.la
endif

test_cookietest_SOURCES = test/cookietest.c
test_cookietest_LDADD = libhipcore/libhipcore.la \
                        libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_cookietest_LDADD += performance/libperformance.la
endif

test_keygentest_SOURCES = test/keygentest.c
test_keygentest_LDADD = libhipcore/libhipcore.la \
                        libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_keygentest_LDADD += performance/libperformance.la
endif

test_hashtest_SOURCES = test/hashtest.c
test_hashtest_LDADD = libhipcore/libhipcore.la \
                      libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_hashtest_LDADD += performance/libperformance.la
endif

test_listtest_SOURCES = test/listtest.c

test_opendhtteststub_SOURCES = test/opendhtteststub.c
test_opendhtteststub_LDADD = libhipcore/libhipcore.la \
                             libhiptool/libhiptool.la \
                             libdht/libhipopendht.la

if HIP_PERFORMANCE
test_opendhtteststub_LDADD += performance/libperformance.la
endif

test_certteststub_SOURCES = test/certteststub.c
test_certteststub_LDADD = libhipcore/libhipcore.la \
                          libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_certteststub_LDADD += performance/libperformance.la
endif

test_sqliteteststub_SOURCES = test/sqliteteststub.c
test_sqliteteststub_LDADD = libhipcore/libhipcore.la \
                            libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_sqliteteststub_LDADD += performance/libperformance.la
endif

test_hc_performance_SOURCES = test/hc_performance.c
test_hc_performance_LDADD = libhipcore/libhipcore.la \
                            libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_hc_performance_LDADD += performance/libperformance.la
endif

test_auth_performance_SOURCES = test/auth_performance.c
test_auth_performance_LDADD = libhipcore/libhipcore.la \
                              libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_auth_performance_LDADD += performance/libperformance.la
endif

if HIP_PERFORMANCE
test_dh_performance_SOURCES = test/dh_performance.c
test_dh_performance_LDADD = libhipcore/libhipcore.la \
                            libhiptool/libhiptool.la \
                            performance/libperformance.la
endif
                 
SUBDIRS += tools hipfwmi

### agent ###
if HIP_AGENT

lib_LTLIBRARIES += libhipgui/libhipgui.la

# NOTE: gtk does not allow for -Wstrict-prototypes, so we need to append AM_CFLAGS
libhipgui_libhipgui_la_CFLAGS = @GTK_CFLAGS@ -Werror -Wall -Wcast-align -Wdisabled-optimization -Wundef -fno-strict-aliasing

libhipgui_libhipgui_la_SOURCES = libhipgui/hipgui.c \
                                 libhipgui/widgets.c \
                                 libhipgui/tools.c \
                                 libhipgui/events.c \
                                 libhipgui/create.c \
                                 libhipgui/dragndrop.c

GTKLDADD = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD = `pkg-config --cflags --libs gobject-2.0`

sbin_PROGRAMS += agent/hipagent

# NOTE: gtk does not allow for -Wstrict-prototypes, so we need to append AM_CFLAGS
agent_hipagent_CFLAGS = @GTK_CFLAGS@ -Werror -Wall -Wcast-align -Wdisabled-optimization -Wundef -fno-strict-aliasing

agent_hipagent_SOURCES = agent/agent.c \
                         agent/tools.c \
                         agent/connhipd.c \
                         agent/hitdb.c \
                         agent/gui_interface.c \
                         agent/str_var.c \
                         agent/language.c

# hard dependencies: libhipgui, libhipcore
# TODO fix dependency between libhipgui and libhipconf if possible
# TODO fix dependency between libhipcore and libhipconf if possible
# TODO fix dependency between libhipconf and libhipopendht if possible
# TODO fix dependency between (libhipconf, libhipcore) and libhiptool if possible
agent_hipagent_LDADD = libhipgui/libhipgui.la \
                       libhipconf/libhipconf.la \
                       libhipcore/libhipcore.la \
                       libhiptool/libhiptool.la \
                       libdht/libhipopendht.la
                 
if HIP_PERFORMANCE
agent_hipagent_LDADD += performance/libperformance.la
endif

agent_hipagent_LDFLAGS = $(GTKLDADD) \
                         $(GTHREADLDADD) \
                         $(GOBJECTLDADD)
endif

### hipd ###

sbin_PROGRAMS += hipd/hipd

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
                    hipd/hipqueue.c \
                    hipd/esp_prot_light_update.c \
                    hipd/nsupdate.c \
                    hipd/hit_to_ip.c \
                    hipd/update_legacy.c \
                    hipd/hadb_legacy.c \
                    hipd/heartbeat.c 

if HIP_MIDAUTH
hipd_hipd_SOURCES +=  hipd/pisa.c
endif

hipd_hipd_LDADD = libhipcore/libhipcore.la \
                  libhipconf/libhipconf.la \
                  libhiptool/libhiptool.la

if HIP_PERFORMANCE
hipd_hipd_LDADD += performance/libperformance.la
endif

if HIP_I3
hipd_hipd_SOURCES += hipd/hi3.c
hipd_hipd_LDADD += i3/i3_client/libi3client.a \
                   i3/i3/libi3.a \
                   i3/utils/libutils.a \
                   i3/aeshash/libaes.a
endif

if HIP_DHT
hipd_hipd_SOURCES += hipd/dht.c
hipd_hipd_LDADD += libdht/libhipopendht.la
endif

if HIP_PFKEY
hipd_hipd_SOURCES += hipd/pfkeyapi.c
hipd_hipd_LDADD += libipsec/libhipsec.la
endif

### firewall ###
if HIP_FIREWALL

sbin_PROGRAMS += firewall/hipfw

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

firewall_hipfw_LDADD = libhipcore/libhipcore.la \
                       libhiptool/libhiptool.la

if HIP_PERFORMANCE
firewall_hipfw_LDADD += performance/libperformance.la
endif

endif # HIP_FIREWALL

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

dist-hook:
	rm -rf `find $(distdir) -name .arch-ids`


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
EXTRA_DIST += doc/HACKING
EXTRA_DIST += doc/doxygen.h doc/Doxyfile
EXTRA_DIST += hipext/hipext.xpi hipext/src/content/hipext.xul hipext/src/content/hipext.js hipext/src/chrome.manifest
EXTRA_DIST += hipext/src/install.rdf hipext/src/config_build.sh hipext/src/build.sh hipext/hipext.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += i3-cfg-PL.xml
EXTRA_DIST += autogen.sh
EXTRA_DIST += $(wildcard agent/*.h)
EXTRA_DIST += $(wildcard i3/aeshash/*.h)
EXTRA_DIST += $(wildcard i3/chord/*.h)
EXTRA_DIST += $(wildcard i3/i3/*.h)
EXTRA_DIST += $(wildcard i3/i3_client/*.h)
EXTRA_DIST += $(wildcard i3/utils/*.h)
EXTRA_DIST += $(wildcard libdht/*.h)
EXTRA_DIST += $(wildcard libhipconf/*.h)
EXTRA_DIST += $(wildcard libhipcore/*.h)
EXTRA_DIST += $(wildcard libhipgui/*.h)
EXTRA_DIST += $(wildcard libhiptool/*.h)
EXTRA_DIST += $(wildcard libipsec/*.h)
EXTRA_DIST += $(wildcard libopphip/*.h)
EXTRA_DIST += $(wildcard performance/*.h)
EXTRA_DIST += $(wildcard libhipandroid/*.{c,h})
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

# Default pkgdatadir is /usr/[local]/share/hipl/pixmaps/hipmanager.png.
# Gtk requires the images without the hipl prefix hence we use ".." below
imagesdir = $(pkgdatadir)/../pixmaps
dist_images_DATA = libhipgui/hipmanager.png

# TODO remove libinet6 after next release
if HIP_LIBINET6
SUBDIRS = libinet6
endif

### bin_PROGRAMS ###
bin_PROGRAMS = test/conntest-client-opp \
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
               test/auth_performance \
               tools/hipconf \
               tools/pisacert

if HIP_PERFORMANCE
bin_PROGRAMS += test/dh_performance
endif

### sbin_PROGRAMS ###
sbin_PROGRAMS = hipd/hipd

if HIP_FIREWALL
sbin_PROGRAMS += firewall/hipfw
endif

if HIP_AGENT
sbin_PROGRAMS += agent/hipagent
endif

### lib_LTLIBRARIES ###
lib_LTLIBRARIES = libhipconf/libhipconf.la \
                  libhipcore/libhipcore.la \
                  libhiptool/libhiptool.la
if HIP_PFKEY
lib_LTLIBRARIES += libipsec/libhipsec.la
endif

if HIP_PERFORMANCE
lib_LTLIBRARIES += performance/libperformance.la
endif

if HIP_OPPORTUNISTIC
lib_LTLIBRARIES += libopphip/libopphip.la
endif

if HIP_DHT
lib_LTLIBRARIES += libdht/libhipopendht.la
endif

if HIP_AGENT
lib_LTLIBRARIES += libhipgui/libhipgui.la
endif

if HIP_I3
noinst_LIBRARIES = i3/aeshash/libaes.a \
                   i3/chord/libchord.a \
                   i3/i3/libi3.a \
                   i3/i3_client/libi3client.a \
                   i3/utils/libutils.a

noinst_PROGRAMS = i3/chord/gen_conf \
                  i3/chord/gen_conf_same \
                  i3/chord/test \
                  i3/chord/chord_getfingers \
                  i3/chord/chord_traceroute
endif # HIP_I3

### *_SOURCES ###
test_conntest_client_opp_SOURCES = test/conntest-client-opp.c \
                                   test/conntest.c

test_conntest_client_hip_SOURCES = test/conntest-client-hip.c \
                                   test/conntest.c

test_conntest_client_native_SOURCES = test/conntest-client-native.c \
                                      test/conntest.c

test_conntest_client_native_user_key_SOURCES = test/conntest-client-native-user-key.c

test_conntest_server_SOURCES = test/conntest-server.c \
                               test/conntest.c

test_conntest_server_native_SOURCES = test/conntest-server-native.c \
                                      test/conntest.c

test_hipsetup_SOURCES = test/hipsetup.c \
                        test/misc_install.c \
                        test/conntest.c

test_first_test_SOURCES = test/first_test.c \
                          test/misc_install.c \
                          test/conntest.c

test_cookietest_SOURCES = test/cookietest.c

test_keygentest_SOURCES = test/keygentest.c

test_hashtest_SOURCES = test/hashtest.c

test_listtest_SOURCES = test/listtest.c

test_opendhtteststub_SOURCES = test/opendhtteststub.c

test_certteststub_SOURCES = test/certteststub.c

test_sqliteteststub_SOURCES = test/sqliteteststub.c

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
                    hipd/hipqueue.c \
                    hipd/esp_prot_light_update.c \
                    hipd/nsupdate.c \
                    hipd/hit_to_ip.c \
                    hipd/update_legacy.c \
                    hipd/hadb_legacy.c \
                    hipd/heartbeat.c 
if HIP_I3
hipd_hipd_SOURCES += hipd/hi3.c
endif

if HIP_DHT
hipd_hipd_SOURCES += hipd/dht.c
endif

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

if HIP_AGENT
# NOTE: gtk does not allow for -Wstrict-prototypes, so we need to append AM_CFLAGS
agent_hipagent_CFLAGS = @GTK_CFLAGS@ -Werror -Wall -Wcast-align -Wdisabled-optimization -Wundef -fno-strict-aliasing

agent_hipagent_SOURCES = agent/agent.c \
                         agent/tools.c \
                         agent/connhipd.c \
                         agent/hitdb.c \
                         agent/gui_interface.c \
                         agent/str_var.c \
                         agent/language.c

# NOTE: gtk does not allow for -Wstrict-prototypes, so we need to append AM_CFLAGS
libhipgui_libhipgui_la_CFLAGS = @GTK_CFLAGS@ -Werror -Wall -Wcast-align -Wdisabled-optimization -Wundef -fno-strict-aliasing

libhipgui_libhipgui_la_SOURCES = libhipgui/hipgui.c \
                                 libhipgui/widgets.c \
                                 libhipgui/tools.c \
                                 libhipgui/events.c \
                                 libhipgui/create.c \
                                 libhipgui/dragndrop.c
endif # HIP_AGENT

libhipconf_libhipconf_la_SOURCES = libhipconf/hipconf.c

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

libhiptool_libhiptool_la_SOURCES = libhiptool/crypto.c \
                                   libhiptool/pk.c \
                                   libhiptool/nlink.c \
                                   libhiptool/lutil.c

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
libipsec_libhipsec_la_SOURCES = libipsec/ipsec_strerror.c \
                                libipsec/pfkey.c \
                               #libipsec/policy_parse.y \
                               #libipsec/policy_token.l

AM_YFLAGS = -d -p __libhipsec
AM_LFLAGS = -P__libhipsec -olex.yy.c

BUILT_SOURCES = libipsec/policy_parse.h

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
#libipsec_la_LDFLAGS = -version-info 0:1:0
#libipsec_la_LIBADD = $(LEXLIB)

#DISTCLEANFILES = policy_parse.c policy_token.c policy_token.h
DISTCLEANFILES = libipsec/policy_token.h

else

# don't use libipsec, but xfrmapi
libhiptool_libhiptool_la_SOURCES += libhiptool/xfrmapi.c

endif # HIPPFKEY

if HIP_PERFORMANCE
performance_libperformance_la_SOURCES = performance/performance.c
endif

if HIP_OPPORTUNISTIC
libopphip_libopphip_la_SOURCES  = libopphip/wrap.c \
                                  libopphip/wrap_db.c
endif

if HIP_DHT
# NOTE: this would overwrite AM_CFLAGS, so we need to append it
libdht_libhipopendht_la_CFLAGS = `xml2-config --cflags` @AM_CFLAGS@

libdht_libhipopendht_la_SOURCES = libdht/libhipopendht.c \
                                  libdht/libhipopendhtxml.c
endif

if HIP_I3
i3_aeshash_libaes_a_SOURCES = i3/aeshash/aescrypp.c \
                              i3/aeshash/aescrypt.c \
                              i3/aeshash/aeshash.c \
                              i3/aeshash/aeskey.c \
                              i3/aeshash/aeskeypp.c \
                              i3/aeshash/aestab.c

i3_chord_libchord_a_SOURCES = i3/chord/api.c \
                              i3/chord/eprintf.c \
                              i3/chord/hosts.c \
                              i3/chord/pack.c \
                              i3/chord/sendpkt.c \
                              i3/chord/chord.c \
                              i3/chord/finger.c \
                              i3/chord/join.c \
                              i3/chord/process.c \
                              i3/chord/stabilize.c \
                              i3/chord/util.c \
                              i3/utils/gen_utils.c 


i3_chord_gen_conf_SOURCES = i3/chord/gen_conf.c

i3_chord_gen_conf_same_SOURCES = i3/chord/gen_conf_same.c

i3_chord_test_SOURCES = i3/chord/test.c

i3_chord_chord_getfingers_SOURCES = i3/chord/chord_getfingers.c \
                                    ${i3_chord_libchord_a_SOURCES}

i3_chord_chord_traceroute_SOURCES = i3/chord/chord_traceroute.c \
                                    ${i3_chord_libchord_a_SOURCES}

# NOTE: this would overwrite AM_CFLAGS, so we need to append it
i3_i3_libi3_a_CFLAGS = `xml2-config --cflags` @AM_CFLAGS@

i3_i3_libi3_a_SOURCES = i3/i3/i3_addr.c \
                        i3/i3/i3_config.c \
                        i3/i3/i3_id.c \
                        i3/i3/i3_options.c \
                        i3/i3/i3_tcp_fns.c \
                        i3/i3/i3_utils.c \
                        i3/i3/i3_api.c \
                        i3/i3/i3_header.c \
                        i3/i3/i3_misc.c \
                        i3/i3/i3_stack.c \
                        i3/i3/i3_trigger.c \
                        i3/i3/i3_ping.c \
                        i3/i3/token_bucket.c

i3_i3_client_libi3client_a_SOURCES = i3/i3_client/downhill_simplex.c \
                                     i3/i3_client/coordinates.c \
                                     i3/i3_client/i3_client_api.c \
                                     i3/i3_client/i3_client_api_ctx.c \
                                     i3/i3_client/i3_client_api_ext.c \
                                     i3/i3_client/i3_client_callback.c \
                                     i3/i3_client/i3_client_context.c \
                                     i3/i3_client/i3_client_fd.c \
                                     i3/i3_client/i3_client_id.c \
                                     i3/i3_client/i3_client_pkt.c \
                                     i3/i3_client/i3_client_timer.c \
                                     i3/i3_client/i3_client_trigger.c \
                                     i3/i3_client/i3server_list.c \
                                     i3/i3_client/ping.c \
                                     i3/i3_client/ping_thread.c \
                                     i3/i3_client/http.c \
                                     i3/i3_client/qsort.c
                                     
i3_utils_libutils_a_SOURCES = i3/utils/byteorder.c \
                              i3/utils/eprintf.c \
                              i3/utils/gen_utils.c \
                              i3/utils/inetfns.c \
                              i3/utils/event.c \
                              i3/utils/netwrap_posix.c

endif # HIP_I3

### *_LDADD ###

test_conntest_client_opp_LDADD = libhipcore/libhipcore.la \
                                 libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_opp_LDADD += performance/libperformance.la
endif

test_conntest_client_hip_LDADD = libhipcore/libhipcore.la \
                                 libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_hip_LDADD += performance/libperformance.la
endif


test_conntest_client_native_LDADD = libhipcore/libhipcore.la \
                                    libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_client_native_LDADD += performance/libperformance.la
endif

test_conntest_client_native_user_key_LDADD = libhipcore/libhipcore.la \
                                             libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_conntest_client_native_user_key_LDADD += performance/libperformance.la
endif

test_conntest_server_LDADD = libhipcore/libhipcore.la \
                             libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_conntest_server_LDADD += performance/libperformance.la
endif

test_conntest_server_native_LDADD = libhipcore/libhipcore.la \
                                    libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_conntest_server_native_LDADD += performance/libperformance.la
endif

test_hipsetup_LDADD = libhipcore/libhipcore.la \
                      libhiptool/libhiptool.la \
                      libhipconf/libhipconf.la
if HIP_DHT
test_hipsetup_LDADD += libdht/libhipopendht.la
endif

if HIP_PERFORMANCE
test_hipsetup_LDADD += performance/libperformance.la
endif

test_first_test_LDADD = libhipcore/libhipcore.la \
                        libhiptool/libhiptool.la \
                        libhipconf/libhipconf.la
if HIP_DHT
test_first_test_LDADD += libdht/libhipopendht.la
endif

if HIP_PERFORMANCE
test_first_test_LDADD += performance/libperformance.la
endif

test_cookietest_LDADD = libhipcore/libhipcore.la \
                        libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_cookietest_LDADD += performance/libperformance.la
endif

test_keygentest_LDADD = libhipcore/libhipcore.la \
                        libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_keygentest_LDADD += performance/libperformance.la
endif

test_hashtest_LDADD = libhipcore/libhipcore.la \
                      libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_hashtest_LDADD += performance/libperformance.la
endif


test_opendhtteststub_LDADD = libhipcore/libhipcore.la \
                             libhiptool/libhiptool.la \
                             libdht/libhipopendht.la

if HIP_PERFORMANCE
test_opendhtteststub_LDADD += performance/libperformance.la
endif

test_certteststub_LDADD = libhipcore/libhipcore.la \
                          libhiptool/libhiptool.la
if HIP_PERFORMANCE
test_certteststub_LDADD += performance/libperformance.la
endif

test_sqliteteststub_LDADD = libhipcore/libhipcore.la \
                            libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_sqliteteststub_LDADD += performance/libperformance.la
endif

test_hc_performance_LDADD = libhipcore/libhipcore.la \
                            libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_hc_performance_LDADD += performance/libperformance.la
endif

test_auth_performance_LDADD = libhipcore/libhipcore.la \
                              libhiptool/libhiptool.la

if HIP_PERFORMANCE
test_auth_performance_LDADD += performance/libperformance.la
endif

if HIP_PERFORMANCE
test_dh_performance_LDADD = libhipcore/libhipcore.la \
                            libhiptool/libhiptool.la \
                            performance/libperformance.la
endif

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

hipd_hipd_LDADD = libhipcore/libhipcore.la \
                  libhipconf/libhipconf.la \
                  libhiptool/libhiptool.la

if HIP_PERFORMANCE
hipd_hipd_LDADD += performance/libperformance.la
endif

if HIP_I3
hipd_hipd_LDADD += i3/i3_client/libi3client.a \
                   i3/i3/libi3.a \
                   i3/utils/libutils.a \
                   i3/aeshash/libaes.a
endif

if HIP_DHT
hipd_hipd_LDADD += libdht/libhipopendht.la
endif

if HIP_PFKEY
hipd_hipd_LDADD += libipsec/libhipsec.la
endif

if HIP_FIREWALL
firewall_hipfw_LDADD = libhipcore/libhipcore.la \
                       libhiptool/libhiptool.la

if HIP_PERFORMANCE
firewall_hipfw_LDADD += performance/libperformance.la
endif

endif # HIP_FIREWALL

if HIP_AGENT

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

GTKLDADD = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD = `pkg-config --cflags --libs gobject-2.0`

agent_hipagent_LDFLAGS = $(GTKLDADD) \
                         $(GTHREADLDADD) \
                         $(GOBJECTLDADD)
endif #HIP_AGENT

if HIP_I3
APP_LDADD = i3/chord/libchord.a

i3_chord_gen_conf_LDADD = $(APP_LDADD)

i3_chord_gen_conf_same_LDADD = $(APP_LDADD)

i3_chord_test_LDADD = $(APP_LDADD)

i3_chord_chord_getfingers_LDADD = $(APP_LADD)

i3_chord_chord_traceroute_LDADD = $(APP_LADD)
endif # HIP_I3

CLEANFILES = tools/hipdnsproxy \
             tools/hipdnskeyparse
             
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

dist-hook:
	rm -rf `find $(distdir) -name .arch-ids`

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
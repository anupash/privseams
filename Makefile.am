ACLOCAL_AMFLAGS  = -I m4

HIPL_HEADER_LIST = $(wildcard $(addprefix $(srcdir)/,agent/*.h firewall/*.h hipd/*.h i3/*/*.h lib/*/*.h test/*.h))

# For "make dist"
#
# XX FIX: use dist_doc_DATA for all documentation (if you change this,
# make sure the check the "make bin" still works)
#
EXTRA_DIST =  .vimrc debian doc hipext hipfwmi patches release.version
EXTRA_DIST += i3/i3-cfg-PL.xml i3/aeshash/aescpp.hh i3/i3/i3_debug.c i3/utils/netwrap_win32.c
EXTRA_DIST += lib/ipsec/policy_parse.c lib/ipsec/policy_parse.y lib/ipsec/policy_token.l
EXTRA_DIST += test/configs test/demo test/maintainer test/openwrt
EXTRA_DIST += test/packaging test/packets test/performance
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/agent/,*.lang))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/lib/dht/,*.txt))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/lib/ipsec/,*.3))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/test/,*.cgi *.pl *.py *.sh))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/tools/,*.cfg *.pl *.py *.sh))
EXTRA_DIST += m4 # required for CentOS "make bin" target
EXTRA_DIST += $(HIPL_HEADER_LIST)

# These are unused, list them here so they appear in the dist tarball.
EXTRA_DIST += test/conntest-client-native.c test/hadb_deprecated.c
EXTRA_DIST += test/hadb_old.c test/misc_install.c

# Default pkgdatadir is /usr/[local]/share/hipl/pixmaps/hipmanager.png.
# Gtk requires the images without the hipl prefix hence we use ".." below
imagesdir = $(pkgdatadir)/../pixmaps
dist_images_DATA = lib/gui/hipmanager.png

### bin_PROGRAMS ###
bin_PROGRAMS = test/auth_performance    \
               test/certteststub        \
               test/conntest-client-opp \
               test/conntest-client-hip \
               test/conntest-server     \
               test/cookietest          \
               test/hashtest            \
               test/hc_performance      \
               test/keygentest          \
               test/listtest            \
               test/sqliteteststub

if HIP_DHT
bin_PROGRAMS += test/dhtteststub
endif

if HIP_PERFORMANCE
bin_PROGRAMS += test/dh_performance
endif

### sbin_PROGRAMS ###
sbin_PROGRAMS = hipd/hipd      \
                tools/hipconf  \
                tools/pisacert

if HIP_FIREWALL
sbin_PROGRAMS += firewall/hipfw
endif

if HIP_AGENT
sbin_PROGRAMS += agent/hipagent
endif

### lib_LTLIBRARIES ###
lib_LTLIBRARIES = lib/conf/libhipconf.la \
                  lib/core/libhipcore.la \
                  lib/tool/libhiptool.la
if HIP_PFKEY
lib_LTLIBRARIES += lib/ipsec/libhipsec.la
endif

if HIP_OPPORTUNISTIC
lib_LTLIBRARIES += lib/opphip/libopphip.la
endif

if HIP_DHT
lib_LTLIBRARIES += lib/dht/libhipdht.la
endif

if HIP_AGENT
lib_LTLIBRARIES += lib/gui/libhipgui.la
endif

if HIP_I3
noinst_LIBRARIES = i3/aeshash/libaes.a        \
                   i3/chord/libchord.a        \
                   i3/i3/libi3.a              \
                   i3/i3_client/libi3client.a \
                   i3/utils/libutils.a

noinst_PROGRAMS = i3/chord/gen_conf         \
                  i3/chord/gen_conf_same    \
                  i3/chord/test             \
                  i3/chord/chord_getfingers \
                  i3/chord/chord_traceroute
endif # HIP_I3

### *_SOURCES ###
test_conntest_client_hip_SOURCES = test/conntest-client-hip.c \
                                   test/conntest.c

test_conntest_client_opp_SOURCES = test/conntest-client-opp.c \
                                   test/conntest.c

test_conntest_server_SOURCES     = test/conntest-server.c     \
                                   test/conntest.c

test_auth_performance_SOURCES = test/auth_performance.c
test_certteststub_SOURCES     = test/certteststub.c
test_cookietest_SOURCES       = test/cookietest.c
test_dh_performance_SOURCES   = test/dh_performance.c
test_dhtteststub_SOURCES      = test/dhtteststub.c
test_hashtest_SOURCES         = test/hashtest.c
test_hc_performance_SOURCES   = test/hc_performance.c
test_keygentest_SOURCES       = test/keygentest.c
test_listtest_SOURCES         = test/listtest.c
test_sqliteteststub_SOURCES   = test/sqliteteststub.c

tools_hipconf_SOURCES  = tools/hipconftool.c
tools_pisacert_SOURCES = tools/pisacert.c

hipd_hipd_SOURCES = hipd/accessor.c              \
                    hipd/blind.c                 \
                    hipd/bos.c                   \
                    hipd/cert.c                  \
                    hipd/close.c                 \
                    hipd/configfilereader.c      \
                    hipd/cookie.c                \
                    hipd/dh.c                    \
                    hipd/dhtqueue.c              \
                    hipd/esp_prot_anchordb.c     \
                    hipd/esp_prot_hipd_msg.c     \
                    hipd/esp_prot_light_update.c \
                    hipd/hadb.c                  \
                    hipd/hadb_legacy.c           \
                    hipd/heartbeat.c             \
                    hipd/hidb.c                  \
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
                    hipd/oppipdb.c               \
                    hipd/output.c                \
                    hipd/registration.c          \
                    hipd/update.c                \
                    hipd/update_legacy.c         \
                    hipd/user.c                  \
                    hipd/user_ipsec_hipd_msg.c   \
                    hipd/user_ipsec_sadb_api.c

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

if HIP_OPPORTUNISTIC
hipd_hipd_SOURCES += hipd/oppdb.c
endif

firewall_hipfw_SOURCES = firewall/cache.c               \
                         firewall/cache_port.c          \
                         firewall/common_hipd_msg.c     \
                         firewall/conntrack.c           \
                         firewall/datapkt.c             \
                         firewall/dlist.c               \
                         firewall/esp_prot_api.c        \
                         firewall/esp_prot_config.c     \
                         firewall/esp_prot_conntrack.c  \
                         firewall/esp_prot_fw_msg.c     \
                         firewall/firewall.c            \
                         firewall/firewall_control.c    \
                         firewall/firewalldb.c          \
                         firewall/helpers.c             \
                         firewall/hslist.c              \
                         firewall/lsi.c                 \
                         firewall/opptcp.c              \
                         firewall/proxy.c               \
                         firewall/proxyconndb.c         \
                         firewall/proxydb.c             \
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

agent_hipagent_SOURCES = agent/agent.c          \
                         agent/connhipd.c       \
                         agent/hitdb.c          \
                         agent/gui_interface.c  \
                         agent/language.c       \
                         agent/str_var.c        \
                         agent/tools.c

lib_gui_libhipgui_la_SOURCES = lib/gui/create.c     \
                               lib/gui/dragndrop.c  \
                               lib/gui/events.c     \
                               lib/gui/hipgui.c     \
                               lib/gui/tools.c      \
                               lib/gui/widgets.c

lib_conf_libhipconf_la_SOURCES = lib/conf/hipconf.c

lib_core_libhipcore_la_SOURCES = lib/core/builder.c         \
                                 lib/core/certtools.c       \
                                 lib/core/crypto.c          \
                                 lib/core/debug.c           \
                                 lib/core/esp_prot_common.c \
                                 lib/core/filemanip.c       \
                                 lib/core/hashchain.c       \
                                 lib/core/hashchain_store.c \
                                 lib/core/hashtable.c       \
                                 lib/core/hashtree.c        \
                                 lib/core/hip_statistics.c  \
                                 lib/core/hip_udp.c         \
                                 lib/core/hit.c             \
                                 lib/core/hostid.c          \
                                 lib/core/hostsfiles.c      \
                                 lib/core/keylen.c          \
                                 lib/core/linkedlist.c      \
                                 lib/core/message.c         \
                                 lib/core/prefix.c          \
                                 lib/core/solve.c           \
                                 lib/core/sqlitedbapi.c     \
                                 lib/core/straddr.c         \
                                 lib/core/transform.c

if HIP_PERFORMANCE
lib_core_libhipcore_la_LIBADD = lib/performance/libperformance.la
endif

if HIP_PRIVSEP
lib_core_libhipcore_la_SOURCES += lib/core/hip_capability.c
endif

lib_tool_libhiptool_la_SOURCES = lib/tool/checksum.c    \
                                 lib/tool/lutil.c       \
                                 lib/tool/nlink.c       \
                                 lib/tool/pk.c

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

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
#lib_ipsec_la_LDFLAGS = -version-info 0:1:0
#lib_ipsec_la_LIBADD = $(LEXLIB)

#DISTCLEANFILES = policy_parse.c policy_token.c policy_token.h
DISTCLEANFILES = lib/ipsec/policy_token.h

# don't use libipsec, but xfrmapi
if HIP_PFKEY
lib_tool_libhiptool_la_SOURCES += lib/tool/pfkeysadb.c
else
lib_tool_libhiptool_la_SOURCES += lib/tool/xfrmapi.c
endif # HIPPFKEY

lib_performance_libperformance_la_SOURCES = lib/performance/performance.c

lib_opphip_libopphip_la_SOURCES  = lib/opphip/wrap.c \
                                   lib/opphip/wrap_db.c

lib_dht_libhipdht_la_SOURCES = lib/dht/libhipdht.c      \
                               lib/dht/libhipdhtxml.c

i3_aeshash_libaes_a_SOURCES = i3/aeshash/aescrypp.c \
                              i3/aeshash/aescrypt.c \
                              i3/aeshash/aeshash.c  \
                              i3/aeshash/aeskey.c   \
                              i3/aeshash/aeskeypp.c \
                              i3/aeshash/aestab.c

i3_chord_libchord_a_SOURCES = i3/chord/api.c        \
                              i3/chord/chord.c      \
                              i3/chord/eprintf.c    \
                              i3/chord/finger.c     \
                              i3/chord/hosts.c      \
                              i3/chord/join.c       \
                              i3/chord/pack.c       \
                              i3/chord/process.c    \
                              i3/chord/sendpkt.c    \
                              i3/chord/stabilize.c  \
                              i3/chord/util.c       \
                              i3/utils/gen_utils.c


i3_chord_chord_getfingers_SOURCES = i3/chord/chord_getfingers.c   \
                                    ${i3_chord_libchord_a_SOURCES}

i3_chord_chord_traceroute_SOURCES = i3/chord/chord_traceroute.c   \
                                    ${i3_chord_libchord_a_SOURCES}

i3_chord_gen_conf_SOURCES      = i3/chord/gen_conf.c
i3_chord_gen_conf_same_SOURCES = i3/chord/gen_conf_same.c
i3_chord_test_SOURCES          = i3/chord/test.c

i3_i3_libi3_a_SOURCES = i3/i3/i3_addr.c     \
                        i3/i3/i3_api.c      \
                        i3/i3/i3_config.c   \
                        i3/i3/i3_header.c   \
                        i3/i3/i3_id.c       \
                        i3/i3/i3_misc.c     \
                        i3/i3/i3_options.c  \
                        i3/i3/i3_ping.c     \
                        i3/i3/i3_stack.c    \
                        i3/i3/i3_tcp_fns.c  \
                        i3/i3/i3_trigger.c  \
                        i3/i3/i3_utils.c    \
                        i3/i3/token_bucket.c

i3_i3_client_libi3client_a_SOURCES = i3/i3_client/coordinates.c         \
                                     i3/i3_client/downhill_simplex.c    \
                                     i3/i3_client/http.c                \
                                     i3/i3_client/i3_client_api.c       \
                                     i3/i3_client/i3_client_api_ctx.c   \
                                     i3/i3_client/i3_client_api_ext.c   \
                                     i3/i3_client/i3_client_callback.c  \
                                     i3/i3_client/i3_client_context.c   \
                                     i3/i3_client/i3_client_fd.c        \
                                     i3/i3_client/i3_client_id.c        \
                                     i3/i3_client/i3_client_pkt.c       \
                                     i3/i3_client/i3_client_timer.c     \
                                     i3/i3_client/i3_client_trigger.c   \
                                     i3/i3_client/i3server_list.c       \
                                     i3/i3_client/ping.c                \
                                     i3/i3_client/ping_thread.c         \
                                     i3/i3_client/qsort.c

i3_utils_libutils_a_SOURCES = i3/utils/byteorder.c      \
                              i3/utils/eprintf.c        \
                              i3/utils/event.c          \
                              i3/utils/gen_utils.c      \
                              i3/utils/inetfns.c        \
                              i3/utils/netwrap_posix.c

### *_LDADD ###

test_conntest_client_opp_LDADD =

if HIP_OPPORTUNISTIC
test_conntest_client_opp_LDADD += lib/opphip/libopphip.la
endif

test_conntest_client_opp_LDADD += lib/core/libhipcore.la \
                                  lib/tool/libhiptool.la

test_conntest_client_hip_LDADD = lib/core/libhipcore.la \
                                 lib/tool/libhiptool.la

test_conntest_server_LDADD = lib/core/libhipcore.la \
                             lib/tool/libhiptool.la

test_cookietest_LDADD = lib/core/libhipcore.la \
                        lib/tool/libhiptool.la

test_keygentest_LDADD = lib/core/libhipcore.la \
                        lib/tool/libhiptool.la

test_hashtest_LDADD = lib/core/libhipcore.la \
                      lib/tool/libhiptool.la

test_dhtteststub_LDADD = lib/dht/libhipdht.la \
                         lib/core/libhipcore.la \
                         lib/tool/libhiptool.la

test_certteststub_LDADD = lib/core/libhipcore.la \
                          lib/tool/libhiptool.la

test_sqliteteststub_LDADD = lib/core/libhipcore.la \
                            lib/tool/libhiptool.la

test_hc_performance_LDADD = lib/core/libhipcore.la \
                            lib/tool/libhiptool.la

test_auth_performance_LDADD = lib/core/libhipcore.la \
                              lib/tool/libhiptool.la

test_dh_performance_LDADD = lib/core/libhipcore.la            \
                            lib/tool/libhiptool.la

tools_hipconf_LDADD = lib/conf/libhipconf.la \
                      lib/core/libhipcore.la \
                      lib/tool/libhiptool.la

if HIP_DHT
tools_hipconf_LDADD += lib/dht/libhipdht.la
endif

tools_pisacert_LDADD = lib/core/libhipcore.la \
                       lib/tool/libhiptool.la

hipd_hipd_LDADD = lib/conf/libhipconf.la \
                  lib/core/libhipcore.la \
                  lib/tool/libhiptool.la

if HIP_I3
hipd_hipd_LDADD += i3/i3_client/libi3client.a \
                   i3/i3/libi3.a              \
                   i3/utils/libutils.a        \
                   i3/aeshash/libaes.a
endif

if HIP_DHT
hipd_hipd_LDADD += lib/dht/libhipdht.la
endif

if HIP_PFKEY
hipd_hipd_LDADD += lib/ipsec/libhipsec.la
endif

firewall_hipfw_LDADD = lib/core/libhipcore.la \
                       lib/tool/libhiptool.la

# hard dependencies: libhipgui, libhipcore
# TODO fix dependency between libhipgui and libhipconf if possible
# TODO fix dependency between libhipcore and libhipconf if possible
# TODO fix dependency between libhipconf and libhipdht if possible
# TODO fix dependency between (libhipconf, libhipcore) and libhiptool if possible
agent_hipagent_LDADD = lib/gui/libhipgui.la   \
                       lib/conf/libhipconf.la \
                       lib/core/libhipcore.la \
                       lib/tool/libhiptool.la
if HIP_DHT
agent_hipagent_LDADD += lib/dht/libhipdht.la
endif

agent_hipagent_LDFLAGS = `pkg-config --libs gtk+-2.0 gthread-2.0`

i3_chord_gen_conf_LDADD       = i3/chord/libchord.a
i3_chord_gen_conf_same_LDADD  = i3/chord/libchord.a
i3_chord_test_LDADD           = i3/chord/libchord.a

CLEANFILES = tools/hipdnsproxy tools/hipdnskeyparse

###### PYTHON stuff below ######
# TODO python parts still needs clean-up
if HAVE_PYTHON
# These two scripts are generated in the end to get the python paths correct.
# Currently, I don't know a better way to deal with the python code. -miika
dist_sbin_SCRIPTS = tools/hipdnskeyparse \
                    tools/hipdnsproxy    \
                    tools/nsupdate.pl

dns_PYTHON = tools/DNS/__init__.py      \
             tools/DNS/Base.py          \
             tools/DNS/Class.py         \
             tools/DNS/lazy.py          \
             tools/DNS/Lib.py           \
             tools/DNS/Opcode.py        \
             tools/DNS/pyip6.py         \
             tools/DNS/Serialization.py \
             tools/DNS/Status.py        \
             tools/DNS/Type.py          \
             tools/DNS/win32dns.py

dnsdir = $(pyexecdir)/tools/DNS

tools_hipdnskeyparse_PYTHON = tools/myasn.py       \
                              tools/parse-key-3.py

tools_hipdnsproxy_PYTHON = tools/dnsproxy.py  \
                           tools/hosts.py     \
                           tools/pyip6.py     \
                           tools/util.py

tools_hipdnskeyparsedir = $(pyexecdir)/tools/hipdnskeyparse
tools_hipdnsproxydir    = $(pyexecdir)/tools/hipdnsproxy
endif # HAVE_PYTHON

doxygen:
	doxygen Doxyfile

nodist_doc_DATA = doc/HOWTO.html doc/HOWTO.txt $(wildcard $(addprefix $(srcdir)/doc/,*.png))

doc/HOWTO.html:  doc/HOWTO.xml
	xmlto -o $(@D) html-nochunks $<

doc/HOWTO.txt: doc/HOWTO.xml
	xmlto -o $(@D) txt $<

CLEANFILES += doc/HOWTO.html doc/HOWTO.txt
clean-local:
	rm -rf doxy

# The olddeb target is for maemo builds only
bin deb increl olddeb rpm syncrepo:
	env PYEXECDIR=$(pyexecdir) @srcdir@/test/packaging/create-package.sh $@

tools/hipdnsproxy: tools/dnsproxy.py
tools/hipdnskeyparse: tools/parse-key-3.py
tools/hipdnsproxy tools/hipdnskeyparse:
	@srcdir@/tools/gen-python-starter.sh $(pyexecdir)/$(@F) $^ $@

autotools-clean: maintainer-clean
	rm -f aclocal.m4 compile config.* configure depcomp install-sh
	rm -f ltmain.sh m4/*.m4 Makefile.in missing py-compile

# Do not check headers that have issues we cannot fix.
NOCHECK_HEADER_LIST  = $(wildcard $(srcdir)/lib/gui/*.h)
HIPL_HEADER_FILTERED = $(filter-out $(NOCHECK_HEADER_LIST),$(HIPL_HEADER_LIST))
HIPL_HEADER_OBJS     = $(subst $(srcdir),$(builddir),$(HIPL_HEADER_FILTERED:.h=.ho))
CLEANFILES          += $(HIPL_HEADER_OBJS)

checkheaders: $(HIPL_HEADER_OBJS)
vpath %.h $(srcdir)
%.ho: %.h
	$(CC) -I$(srcdir) -I$(builddir) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

i3/i3/i3_config.o lib/dht/libhipdhtxml.lo: CFLAGS += `xml2-config --cflags`
lib/gui/%: CFLAGS += @GTK_CFLAGS@ -Wno-strict-prototypes

.PHONY: bin checkheaders deb doxygen increl olddeb rpm syncrepo

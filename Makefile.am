ACLOCAL_AMFLAGS  = -I m4

HIPL_HEADER_LIST = $(wildcard $(addprefix $(srcdir)/,agent/*.h firewall/*.h hipd/*.h i3/*/*.h lib/*/*.h))

# For "make dist"
EXTRA_DIST =  .vimrc debian doc patches release.version version.h
EXTRA_DIST += i3/i3-cfg-PL.xml i3/aeshash/aescpp.hh i3/i3/i3_debug.c i3/utils/netwrap_win32.c
EXTRA_DIST += lib/ipsec/policy_parse.c lib/ipsec/policy_parse.y lib/ipsec/policy_token.l
EXTRA_DIST += packaging tools/maintainer
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/agent/,*.lang))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/lib/dht/,*.txt))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/lib/ipsec/,*.3))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/test/,*.pl *.sh))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/tools/,*.cfg *.pl *.sh))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/firewall/,*.cfg))
EXTRA_DIST += $(HIPL_HEADER_LIST)

# Default pkgdatadir is /usr/[local]/share/hipl/pixmaps/hipmanager.png.
# Gtk requires the images without the hipl prefix hence we use ".." below
imagesdir = $(pkgdatadir)/../pixmaps
dist_images_DATA = lib/gui/hipmanager.png


### user programs ###
bin_PROGRAMS = test/auth_performance    \
               test/certteststub        \
               test/hc_performance

if HIP_DHT
bin_PROGRAMS += test/dhtteststub
endif

if HIP_PERFORMANCE
bin_PROGRAMS += test/dh_performance
endif

if HIP_I3
noinst_PROGRAMS = i3/chord/chord_getfingers \
                  i3/chord/chord_traceroute \
                  i3/chord/gen_conf         \
                  i3/chord/gen_conf_same    \
                  i3/chord/test
endif


### superuser programs ###
sbin_PROGRAMS = hipd/hipd      \
                tools/hipconf  \
                tools/pisacert

if HIP_FIREWALL
sbin_PROGRAMS += firewall/hipfw
endif

if HIP_AGENT
sbin_PROGRAMS += agent/hipagent
endif


### libraries ###
lib_LTLIBRARIES = lib/core/libhipcore.la

if HIP_PFKEY
lib_LTLIBRARIES += lib/ipsec/libhipsec.la
endif

if HIP_OPPORTUNISTIC
lib_LTLIBRARIES += lib/opphip/libopphip.la
endif

if HIP_AGENT
lib_LTLIBRARIES += lib/gui/libhipgui.la
endif

if HIP_I3
lib_LTLIBRARIES += i3/libi3.la \
                   i3/chord/libchord.la
endif

### source declarations ###

test_auth_performance_SOURCES = test/auth_performance.c
test_certteststub_SOURCES     = test/certteststub.c
test_dh_performance_SOURCES   = test/dh_performance.c
test_dhtteststub_SOURCES      = test/dhtteststub.c
test_hc_performance_SOURCES   = test/hc_performance.c

tools_hipconf_SOURCES  = tools/hipconf.c
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
hipd_hipd_SOURCES += hipd/oppdb.c                \
                     hipd/oppipdb.c
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


# TODO: libhipcore, libhipconf, libhipdht and libhiptool have circular
# dependencies. This needs to be addressed at some point.
lib_core_libhipcore_la_SOURCES = lib/conf/conf.c            \
                                 lib/core/builder.c         \
                                 lib/core/capability.c      \
                                 lib/core/certtools.c       \
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
                                 lib/tool/pk.c

if HIP_AGENT
lib_core_libhipcore_la_SOURCES += lib/core/sqlitedbapi.c
endif

if HIP_DHT
lib_core_libhipcore_la_SOURCES += lib/dht/libhipdht.c      \
                                  lib/dht/libhipdhtxml.c
endif

if HIP_PERFORMANCE
lib_core_libhipcore_la_SOURCES += lib/core/performance.c
endif

# don't use libipsec, but xfrmapi
if HIP_PFKEY
lib_core_libhipcore_la_SOURCES += lib/tool/pfkeysadb.c
else
lib_core_libhipcore_la_SOURCES += lib/tool/xfrmapi.c
endif # HIPPFKEY

lib_opphip_libopphip_la_SOURCES  = lib/opphip/wrap.c \
                                   lib/opphip/wrap_db.c

i3_libi3_la_SOURCES = i3/aeshash/aescrypt.c              \
                      i3/aeshash/aeshash.c               \
                      i3/aeshash/aeskey.c                \
                      i3/aeshash/aeskeypp.c              \
                      i3/aeshash/aestab.c                \
                      i3/i3/i3_addr.c                    \
                      i3/i3/i3_api.c                     \
                      i3/i3/i3_config.c                  \
                      i3/i3/i3_header.c                  \
                      i3/i3/i3_id.c                      \
                      i3/i3/i3_misc.c                    \
                      i3/i3/i3_options.c                 \
                      i3/i3/i3_ping.c                    \
                      i3/i3/i3_stack.c                   \
                      i3/i3/i3_tcp_fns.c                 \
                      i3/i3/i3_trigger.c                 \
                      i3/i3/i3_utils.c                   \
                      i3/i3/token_bucket.c               \
                      i3/i3_client/coordinates.c         \
                      i3/i3_client/downhill_simplex.c    \
                      i3/i3_client/http.c                \
                      i3/i3_client/i3_client_api.c       \
                      i3/i3_client/i3_client_api_ctx.c   \
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
                      i3/i3_client/qsort.c               \
                      i3/utils/byteorder.c               \
                      i3/utils/eprintf.c                 \
                      i3/utils/event.c                   \
                      i3/utils/gen_utils.c               \
                      i3/utils/inetfns.c                 \
                      i3/utils/netwrap_posix.c

i3_chord_libchord_la_SOURCES = i3/chord/api.c        \
                               i3/chord/chord.c      \
                               i3/chord/finger.c     \
                               i3/chord/hosts.c      \
                               i3/chord/join.c       \
                               i3/chord/pack.c       \
                               i3/chord/process.c    \
                               i3/chord/sendpkt.c    \
                               i3/chord/stabilize.c  \
                               i3/chord/util.c       \
                               i3/utils/eprintf.c    \
                               i3/utils/gen_utils.c

i3_chord_chord_getfingers_SOURCES = i3/chord/chord_getfingers.c
i3_chord_chord_traceroute_SOURCES = i3/chord/chord_traceroute.c
i3_chord_gen_conf_SOURCES         = i3/chord/gen_conf.c
i3_chord_gen_conf_same_SOURCES    = i3/chord/gen_conf_same.c
i3_chord_test_SOURCES             = i3/chord/test.c

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
#lib_ipsec_libhipsec_la_LDFLAGS = -version-info 0:1:0
#lib_ipsec_libhipsec_la_LIBADD  = $(LEXLIB)

#DISTCLEANFILES = lib/ipsec/policy_parse.c lib/ipsec/policy_token.c

### library dependencies ###

firewall_hipfw_LDADD           = lib/core/libhipcore.la
hipd_hipd_LDADD                = lib/core/libhipcore.la
test_auth_performance_LDADD    = lib/core/libhipcore.la
test_certteststub_LDADD        = lib/core/libhipcore.la
test_dh_performance_LDADD      = lib/core/libhipcore.la
test_dhtteststub_LDADD         = lib/core/libhipcore.la
test_hc_performance_LDADD      = lib/core/libhipcore.la
tools_hipconf_LDADD            = lib/core/libhipcore.la
tools_pisacert_LDADD           = lib/core/libhipcore.la

if HIP_I3
hipd_hipd_LDADD += i3/libi3.la
endif

if HIP_PFKEY
hipd_hipd_LDADD += lib/ipsec/libhipsec.la
endif

agent_hipagent_LDADD = lib/gui/libhipgui.la   \
                       lib/core/libhipcore.la

agent_hipagent_LDFLAGS = `pkg-config --libs gtk+-2.0 gthread-2.0`

i3_chord_chord_getfingers_LDADD = i3/chord/libchord.la
i3_chord_chord_traceroute_LDADD = i3/chord/libchord.la
i3_chord_gen_conf_LDADD         = i3/chord/libchord.la
i3_chord_gen_conf_same_LDADD    = i3/chord/libchord.la
i3_chord_test_LDADD             = i3/chord/libchord.la


if HAVE_PYTHON
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
endif # HAVE_PYTHON


### misc stuff ###
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
	rm -rf doc/doxy

deb increl rpm syncrepo:
	env PYEXECDIR=$(pyexecdir) @srcdir@/packaging/create-package.sh $@

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
	$(CC) -I$(srcdir) -I$(builddir) $(AM_CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

i3/i3/i3_config.lo lib/dht/libhipdhtxml.lo: CFLAGS += `xml2-config --cflags`
lib/gui/%: CFLAGS += @GTK_CFLAGS@ -Wno-strict-prototypes

# Ensure that version.h is created before everything else. This does not work
# when creating specific objects that may depend on version.h directly.
BUILT_SOURCES = version.h
$(srcdir)/version.h: $(wildcard $(srcdir)/.bzr/branch/last-revision)
	echo "$$(bzr version-info $(srcdir) --custom --template="#define BZR_REVISION \"{revno}\"\n\n#define BZR_BRANCH \"{branch_nick}\"")" > $@

# The complete doc/ subdirectory is in EXTRA_DIST, so files that should
# not be distributed need to be deleted manually from the distribution.
dist-hook:
	rm -f $(distdir)/doc/Doxyfile

.PHONY: checkheaders deb doxygen increl rpm syncrepo

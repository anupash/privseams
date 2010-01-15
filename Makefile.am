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
EXTRA_DIST += libhipgui/hipmanager.png doc/HACKING
EXTRA_DIST += doc/doxygen.h doc/Doxyfile
EXTRA_DIST += hipext/hipext.xpi hipext/src/content/hipext.xul hipext/src/content/hipext.js hipext/src/chrome.manifest
EXTRA_DIST += hipext/src/install.rdf hipext/src/config_build.sh hipext/src/build.sh hipext/hipext.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += i3-cfg-PL.xml
EXTRA_DIST += autogen.sh
EXTRA_DIST += $(wildcard libhipandroid/*.{c,h})
EXTRA_DIST += $(wildcard hipd/*.h)
EXTRA_DIST += $(wildcard firewall/*.h)

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

SUBDIRS =

if HIP_LIBINET6
SUBDIRS += libinet6
endif

SUBDIRS += libhipcore \
          libhiptool \
          libhipconf

if HIP_PFKEY
SUBDIRS += libipsec
endif

if HIP_OPPORTUNISTIC
SUBDIRS += libopphip
endif

if HIP_DHT
SUBDIRS += libdht
endif

if HIP_PERFORMANCE
SUBDIRS += performance
endif

if HIP_I3
SUBDIRS += i3
endif

SUBDIRS += tools test hipfwmi

if HIP_AGENT
SUBDIRS += libhipgui \
           agent
endif

### subdirectory hipd ###

sbin_PROGRAMS = hipd/hipd

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

hipd_hipd_LDADD = libhipcore/.libs/libhipcore.a \
                  libhipconf/.libs/libhipconf.a \
                  libhiptool/.libs/libhiptool.a

if HIP_PERFORMANCE
hipd_hipd_LDADD += performance/.libs/libperformance.a
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
hipd_hipd_LDADD += libdht/.libs/libhipopendht.a
endif

if HIP_PFKEY
hipd_hipd_SOURCES += hipd/pfkeyapi.c
hipd_hipd_LDADD += libipsec/.libs/libhipsec.a
endif

### subdirectory firewall ###
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

firewall_hipfw_LDADD = libhipcore/.libs/libhipcore.a \
                       libhiptool/.libs/libhiptool.a

if HIP_PERFORMANCE
firewall_hipfw_LDADD += performance/.libs/libperformance.a
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


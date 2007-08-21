AUTOMAKE_OPTIONS = foreign

# For "make dist"
EXTRA_DIST =  doc/COPYING doc/HACKING doc/HOWTO.xml doc/drafts doc/Makefile
EXTRA_DIST += doc/README doc/design_choices.bib test/configs patches
EXTRA_DIST += hipsock jip
EXTRA_DIST += test/packaging/create-deb.sh test/packaging/create-rpm.sh test/packaging/hipl.spec
EXTRA_DIST += test/packaging/rh-init.d-hipd test/packaging/debian-init.d-hipd
# The design choices doc is currently depracated
EXTRA_DIST += doc/design_choices.tex doc/hipl.tex doc/acronyms.tex
EXTRA_DIST += doc/design_choices_macros.tex doc/catalogue.tex doc/fig
EXTRA_DIST += libhipgui/logo.png libhipgui/newhit.png libhipgui/run.png libhipgui/swtool.png libhipgui/newgroup.png libhipgui/hipstart.conf
EXTRA_DIST += libhipgui/stock_id_24.png libhipgui/stock_id_48.png libhipgui/stock_keyring_24.png libhipgui/stock_keyring_48.png libhipgui/exec.png
EXTRA_DIST += doc/doxygen.h doc/Doxyfile showip/showip-hipmod-0.8.02-fx-mz.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += i3-cfg-PL.xml

# Andrei: please insert i3 after OpenDHT after it works. Remove this line
#
# Note: libinet6 has to be the first one
#
SUBDIRS = libinet6 libhiptool libopphip libipsec opendht i3 tools hipd test firewall libhipgui agent

showip:
	cd showip && sh create.sh
doxygen:
	cd doc && doxygen

rpm:
	test/packaging/create-rpm.sh
deb:
	test/packaging/create-deb.sh
#	test/packaging/create-deb.sh -s

armel-deb:
	test/packaging/create-deb.sh -a

source-deb:
	test/packaging/create-deb.sh -s

agent-deb:
	test/packaging/create-agent-deb.sh -s

corporate-deb:
	test/packaging/create-deb.sh -c

dist-hook:
	rm -rf `find $(distdir) -name .arch-ids`

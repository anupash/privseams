
AUTOMAKE_OPTIONS = foreign

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
EXTRA_DIST += libhipgui/hipmanager.png
EXTRA_DIST += doc/doxygen.h doc/Doxyfile showip/showip-hipmod-0.8.02-fx-mz.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += i3-cfg-PL.xml
EXTRA_DIST += autogen.sh
EXTRA_DIST += @PJPROJECT_FILES@

CLEANFILES = pjproject/pjlib/lib/libpj-hipl.a \
             pjproject/pjnath/lib/libpjnath-hipl.a \
             pjproject/pjlib-util/lib/libpjlib-util-hipl.a

# Note: libinet6 has to be the first one
#
SUBDIRS = pjproject libinet6 libhiptool libopphip libipsec opendht tools
if HIP_I3
SUBDIRS += i3
endif
SUBDIRS += hipd test firewall libhipgui agent hipfwmi

showip:
	cd showip && sh create.sh
doxygen:
	cd doc && doxygen
rpm:
	test/packaging/create-package.sh rpm
deb:
	test/packaging/create-package.sh deb

dist-hook:
	rm -rf `find $(distdir) -name .arch-ids`


AUTOMAKE_OPTIONS = foreign

# For "make dist"
EXTRA_DIST =  doc/COPYING doc/HACKING doc/HOWTO.xml doc/drafts doc/Makefile
EXTRA_DIST += doc/README doc/design_choices.bib test/configs patches
EXTRA_DIST += hipsock jip test/packaging
# The design choices doc is currently depracated
EXTRA_DIST += doc/design_choices.tex doc/hipl.tex doc/acronyms.tex
EXTRA_DIST += doc/design_choices_macros.tex doc/catalogue.tex doc/fig
EXTRA_DIST += libhipgui/logo.png libhipgui/run.png libhipgui/swtool.png libhipgui/newgroup.png libhipgui/hipstart.conf
EXTRA_DIST += doc/doxygen.h doc/Doxyfile

# Note: libinet6 has to be the first one
#
SUBDIRS = libinet6 libhiptool libopphip opendht tools hipd test firewall libhipgui agent

doxygen:
	cd doc && doxygen

rpm:
	test/packaging/create-rpm.sh
deb:
	test/packaging/create-deb.sh
	test/packaging/create-deb.sh -s

AUTOMAKE_OPTIONS = foreign

# For "make dist"
EXTRA_DIST = doc/COPYING doc/HACKING doc/HOWTO.xml doc/drafts doc/Makefile
EXTRA_DIST += doc/README doc/design_choices.bib test/configs patches
EXTRA_DIST += hipsock jip test/packaging
# The design choices doc is currently depracated
EXTRA_DIST += doc/design_choices.tex doc/hipl.tex doc/acronyms.tex
EXTRA_DIST += doc/design_choices_macros.tex doc/catalogue.tex doc/fig

# Note: libinet6 has to be the first one
#
SUBDIRS = libinet6 libhiptool tools hipd test firewall libhipgui agent

rpm:
	test/packaging/create-rpm.sh
deb:
	test/packaging/create-deb.sh

dist-hook:
	rm -rf `find $(distdir) -name '{arch}'`
	rm -rf `find $(distdir) -name '.arch-ids'`
	rm -rf `find $(distdir) -name .arch-inventory`
	rm -rf `find $(distdir) -name ",,*"`
	rm -rf `find $(distdir) -name .deps`

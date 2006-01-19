AUTOMAKE_OPTIONS = foreign

# For "make dist"
EXTRA_DIST = doc/COPYING doc/design_choices.tex doc/hipl.tex doc/HACKING
EXTRA_DIST += doc/acronyms.tex doc/design_choices_macros.tex
EXTRA_DIST += doc/HOWTO.xml doc/catalogue.tex doc/drafts doc/Makefile doc/fig
EXTRA_DIST += doc/README doc/design_choices.bib test/configs patches

# Note: libinet6 has to be the first one
#
SUBDIRS = libinet6 libhiptool tools hipd test $(hipl_opt_build)

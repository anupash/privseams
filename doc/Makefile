###############################################################################
#
# TODO:
# - xx
#
### VARIABLE DECLARATIONS  ####################################################

LATEX    = latex
DVIPS    = dvips
FIG2DEV  = fig2dev
BIBTEX   = bibtex
DVIPDF   = dvipdf
PDFLATEX = pdflatex
PERL     = perl

APISOURCES = ../tools/crypto.c ../tools/debug.c \
             ../tools/hipconf.c ../tools/message.c \
             ../linux/net/ipv6/hip/builder.c ../tools/hipconf.c \
             ../linux/net/ipv6/hip/unit.c
API        = hipl-userspace-api
LINUX      = ../linux

FIGS = fig/collaboration.fig fig/hooks.fig fig/kernel_model.fig \
       fig/input.fig fig/output.fig fig/base_exchange.fig \
       fig/stack_model.fig fig/rea.fig

BIBS                   = design_choices.bib
DESIGN_CHOICES_SOURCES = catalogue.tex design_choices_macros.tex hipl.tex
DESIGN_CHOICES         = design_choices

### COMPILATION RULESETS ######################################################

%.dvi:	%.tex
	$(LATEX) $*
	$(BIBTEX) $(BIBS:.bib=)
	$(LATEX) $*
	$(LATEX) $*

%.pdf:	%.tex
	$(PDFLATEX) $*
	$(BIBTEX) $(BIBS:.bib=)
	$(PDFLATEX) $*
	$(PDFLATEX) $*

%.eps: %.fig
	$(FIG2DEV) -Leps $< $@

%.pdf: %.fig
	$(FIG2DEV) -L pdf $*.fig $*.pdf

%.ps:   %.dvi
	$(DVIPS) -o $*.ps $*.dvi

%.sgml: %.c
	echo "<programlisting>" > $@
	expand --tabs=8 < $< | \
	sed -e "s/&/\\&amp;/g" \
		-e "s/</\\&lt;/g" \
		-e "s/>/\\&gt;/g" >> $@
	echo "</programlisting>" >> $@

%.ps : %.sgml
	@(which db2ps > /dev/null 2>&1) || \
		(echo "*** You need to install DocBook stylesheets ***"; \
			exit 1)
		db2ps $<

%.pdf : %.sgml
	@(which db2pdf > /dev/null 2>&1) || \
		(echo "*** You need to install DocBook stylesheets ***"; \
			exit 1)
		db2pdf $<

%:      %.sgml
	@(which db2html > /dev/null 2>&1) || \
		(echo "*** You need to install DocBook stylesheets ***"; \
			exit 1)
		rm -rf $@
		db2html $<
		if [ ! -z "$(PNG-$@)" ]; then cp $(PNG-$@) $@; fi

### TARGETS ##################################################################

all:	$(DESIGN_CHOICES).dvi $(DESIGN_CHOICES).ps $(DESIGN_CHOICES).pdf \
	$(API).ps $(API).pdf

$(DESIGN_CHOICES).dvi:	$(DESIGN_CHOICES).tex $(DESIGN_CHOICES_SOURCES) \
			$(FIGS:.fig=.eps)

$(DESIGN_CHOICES).pdf:	$(DESIGN_CHOICES).tex $(DESIGN_CHOICES_SOURCES) \
			$(FIGS:.fig=.pdf)

$(DESIGN_CHOICES).ps:	$(DESIGN_CHOICES).dvi

# Not really needed.
#man:    api-man

$(API).sgml: docproc $(API).tmpl $(APISOURCES)
	@chmod 755 $(LINUX)/scripts/docgen
	@chmod 755 $(LINUX)/scripts/gen-all-syms
	@chmod 755 $(LINUX)/scripts/kernel-doc
	TOPDIR=$(LINUX) $(LINUX)/scripts/docgen $(APISOURCES) \
		< $(API).tmpl >$(API).sgml

docproc: $(LINUX)/scripts/docproc.o
	${CC} -o $(LINUX)/scripts/docproc $(LINUX)/scripts/docproc.o

clean:
	rm -f *~ *.aux *.log *.toc *.bbl *.blg *.ps *.dvi *.pdf *.out
	rm -f $(patsubst %.fig, %.eps, $(FIGS))
	rm -f $(API).sgml $(API).tex

.phony: clean books sgml2ps sgml2pdf sgml2html

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

LINUX      = ../linux

FIGS = fig/collaboration.fig fig/hooks.fig fig/kernel_model.fig \
       fig/input.fig fig/output.fig fig/base_exchange.fig \
       fig/stack_model.fig fig/mm-update.fig

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

### TARGETS ##################################################################

all:	$(DESIGN_CHOICES).dvi $(DESIGN_CHOICES).ps $(DESIGN_CHOICES).pdf

$(DESIGN_CHOICES).dvi:	$(DESIGN_CHOICES).tex $(DESIGN_CHOICES_SOURCES) \
			$(FIGS:.fig=.eps)

$(DESIGN_CHOICES).pdf:	$(DESIGN_CHOICES).tex $(DESIGN_CHOICES_SOURCES) \
			$(FIGS:.fig=.pdf)

$(DESIGN_CHOICES).ps:	$(DESIGN_CHOICES).dvi

clean:
	rm -f *~ *.aux *.log *.toc *.bbl *.blg *.ps *.dvi *.pdf *.out
	rm -f $(patsubst %.fig, %.eps, $(FIGS))

.phony: clean

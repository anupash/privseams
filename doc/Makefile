###############################################################################
#
# TODO:
# - move this to Makefile.am
#
### VARIABLE DECLARATIONS  ####################################################

XMLTO    = xmlto

HOWTO                  = HOWTO
HOWTO_HTML_DIR         = howto-html

DOCDIR_PREFIX = /usr/share/doc
DOCDIR = $(DOCDIR_PREFIX)/hipl

### COMPILATION RULESETS ######################################################

%.txt:   %.xml
	$(XMLTO) txt $<

%.html:  %.xml
	$(XMLTO) -o $(HOWTO_HTML_DIR) html $<

### TARGETS ##################################################################

all: $(HOWTO).txt $(HOWTO).html \

$(HOWTO).txt: $(HOWTO).xml
$(HOWTO).html: $(HOWTO).xml

clean:
	rm -f HOWTO.txt
	rm -rf $(HOWTO_HTML_DIR)

install: all
	@echo
	@echo "** Copying documentation files to $(DOCDIR) **"
	@echo
	mkdir -p $(DOCDIR)
	cp $(HOWTO).txt $(DOCDIR)
	cp -a $(HOWTO_HTML_DIR) $(DOCDIR)
	cp docshot-*.png $(DOCDIR)
	cp base-exchange-*.png $(DOCDIR)

.phony: clean

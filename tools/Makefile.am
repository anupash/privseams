AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = hipconf \
                pisacert
                
hipconf_SOURCES = hipconftool.c
pisacert_SOURCES = pisacert.c

hipconf_LDADD = ../libhipcore/.libs/libhipcore.a \
                ../libhiptool/.libs/libhiptool.a \
                ../libhipconf/.libs/libhipconf.a
                
pisacert_LDADD = ../libhipcore/.libs/libhipcore.a \
                 ../libhiptool/.libs/libhiptool.a

# required by libhipconf
if HIP_DHT
hipconf_LDADD += ../libdht/.libs/libhipopendht.a
endif


###### PYTHON stuff below ######

CLEANFILES = hipdnsproxy hipdnskeyparse

EXTRA_DIST = gen-python-starter.sh \
             $(wildcard *.h)

# TODO python parts still needs clean-up
if HAVE_PYTHON

# These two scripts are generated in the end to get the python paths correct.
# Currently, I don't know a better way to deal with the python code. -miika
dist_sbin_SCRIPTS = hipdnsproxy hipdnskeyparse nsupdate.pl

dns_PYTHON = DNS/Base.py DNS/Lib.py DNS/Type.py DNS/Class.py
dns_PYTHON += DNS/Opcode.py DNS/win32dns.py DNS/__init__.py
dns_PYTHON += DNS/pyip6.py DNS/lazy.py DNS/Status.py
dns_PYTHON += DNS/Serialization.py
dnsdir = $(pyexecdir)/DNS

hipdnsproxy_PYTHON = dnsproxy.py pyip6.py hosts.py util.py
hipdnsproxydir = $(pyexecdir)/hipdnsproxy

hipdnskeyparse_PYTHON = parse-key-3.py myasn.py
hipdnskeyparsedir = $(pyexecdir)/hipdnskeyparse

endif
 
# TODO directly stating targets seems wrong in Makefile.am - Rene

# Automake does not build the shell scripts without this
hipdnsproxy:
	@sh gen-python-starter.sh $(pyexecdir)/hipdnsproxy dnsproxy.py hipdnsproxy

hipdnskeyparse:
	@sh gen-python-starter.sh $(pyexecdir)/hipdnskeyparse parse-key-3.py hipdnskeyparse

# This workaround forces automake to generate the scripts on each run. It is
# necessary because otherwise "make rpm" target has the old $pyexecdir from
# "make dist" and it refuses to build the scripts again.
all-local:
	@rm -f hipdnsproxy
	@rm -f hipdnskeyparse
	@sh gen-python-starter.sh $(pyexecdir)/hipdnsproxy dnsproxy.py hipdnsproxy
	@sh gen-python-starter.sh $(pyexecdir)/hipdnskeyparse parse-key-3.py hipdnskeyparse

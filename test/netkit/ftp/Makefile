# Generated automatically from Makefile.in by configure.
##
## settings
##
prefix=/usr/local/v6
exec_prefix=${prefix}
sbindir=${exec_prefix}/sbin
bindir=${exec_prefix}/bin
mandir=${prefix}/man

##
## autoconf
##
CPP=gcc -E
CXXCPP=@CXXCPP@
CC=gcc
CXX=@CXX@
DEFS=-D_USAGI -DINET6  
CFLAGS=-I../libinet6/include -g -O2 -I../../../tools -I../../../libinet6/include -I../../.. -I../../../linux/include -I../../../linux/net/ipv6/hip -DHIP_NATIVE -g $(DEFS)
CXXFLAGS= $(DEFS)

OBJS=
LIBOBJS=@LIBOBJS@
LDFLAGS=
LIBS=-L../../../libinet6 -linet6 -lcrypto -L../libinet6 -linet6 

INSTALL=/usr/bin/install -c
INSTALL_PROG=${INSTALL}
INSTALL_DATA=${INSTALL} -m 644
INSTALL_DIR=${INSTALL} -d

LN_S=ln -s

##
## targets
##
TARGET = ftp

all:	$(TARGET)

clean:
	-rm -f *.o $(TARGET)
distclean: clean
	-rm -f config.*
	-rm -f Makefile

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROG) -s ftp $(bindir)
	$(LN_S) -f ftp $(bindir)/pftp
	$(INSTALL_DIR) $(mandir)/man1
	$(INSTALL_DATA) ftp.1 $(mandir)/man1
	$(LN_S) -f ftp.1 $(mandir)/man1/pftp.1
	$(INSTALL_DIR) $(mandir)/man5
	$(INSTALL_DATA) netrc.5 $(mandir)/man5
##
## dependencies
##
ifeq ($(USE_READLINE),1)
CFLAGS += -D__USE_READLINE__
LIBS += -lreadline $(LIBTERMCAP)
endif

ftp: cmds.o cmdtab.o domacro.o ftp.o glob.o main.o ruserpass.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

domacro.o ftp.o glob.o main.o ruserpass.o: ftp_var.h pathnames.h
cmds.o cmdtab.o: ftp_var.h pathnames.h cmds.h
cmds.o glob.o: glob.h


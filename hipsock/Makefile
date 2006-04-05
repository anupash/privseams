obj-m += hipsock.o
hipsock-objs := debug.o builder.o misc.o eid_db.o af_hip.o


# Default assumption of the linux sources. Do not change! Use the
# command line option.
#
LINUX=/usr/src/linux
LIBHIPTOOL=../libhiptool
HIPD=../hipd
LN=ln -sf

all:	warn links
	CFLAGS=-I../hipd make -C $(LINUX) M=$(PWD) modules

links:
	$(LN) $(LIBHIPTOOL)/builder.c
	$(LN) $(LIBHIPTOOL)/builder.h
	$(LN) $(LIBHIPTOOL)/hip.h
	$(LN) $(HIPD)/hidb.h
	$(LN) $(LIBHIPTOOL)/misc.c
	$(LN) $(LIBHIPTOOL)/misc.h
	$(LN) $(HIPD)/timer.h

warn:
	@echo ""
	@echo "##########################################################"
	@echo "# Default assumption of kernel sources in /usr/src/linux #"
	@echo "# Override with make LINUX=/path/to/linux/sources        #"
	@echo "##########################################################"
	@echo ""

clean:
	make -C $(LINUX) M=$(PWD) clean

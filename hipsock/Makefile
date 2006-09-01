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
	$(LN) $(LIBHIPTOOL)/protodefs.h
	$(LN) $(LIBHIPTOOL)/utils.h
	$(LN) $(LIBHIPTOOL)/misc.c
	$(LN) $(LIBHIPTOOL)/misc.h
	$(LN) $(LIBHIPTOOL)/state.h
	$(LN) $(LIBHIPTOOL)/icomm.h
	$(LN) $(LIBHIPTOOL)/ife.h
	$(LN) $(HIPD)/timer.h
	$(LN) $(HIPD)/hidb.h

warn:
	@echo ""
	@echo "##########################################################"
	@echo "# Default assumption of kernel sources in /usr/src/linux #"
	@echo "# Override with make LINUX=/path/to/linux/sources        #"
	@echo "##########################################################"
	@echo ""

clean:
	make -C $(LINUX) M=$(PWD) clean

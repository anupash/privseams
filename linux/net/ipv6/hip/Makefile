#
# Makefile for the HIP for Linux.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definition is now in the main makefile...

O_TARGET := hipmod.o

#EXTRA_CFLAGS := -DKRISUS_THESIS

obj-y := hip.o daemon.o ioctl.o builder.o keymat.o unit.o test.o input.o output.o \
	 db.o debug.o cookie.o workqueue.o misc.o security.o socket.o crypto/cryptocode.o

obj-$(CONFIG_HIP) := $(O_TARGET)

crypto/cryptocode.o:
	$(MAKE) -C crypto $(MAKECMDGOALS)


include $(TOPDIR)/Rules.make

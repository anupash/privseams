#
# Makefile for the HIP for Linux.
#

#EXTRA_CFLAGS := -DKRISUS_THESIS

obj-$(CONFIG_HIP) += hipmod.o

hipmod-objs := hip.o daemon.o ioctl.o builder.o keymat.o unit.o test.o input.o output.o \
	       db.o debug.o cookie.o workqueue.o misc.o security.o socket.o crypto/cryptocode.o

#crypto/cryptocode.o:
#	$(MAKE) -C crypto $(MAKECMDGOALS)


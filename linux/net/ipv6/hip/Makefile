#
# Makefile for the HIP for Linux.
#

obj-$(CONFIG_HIP) += hipmod.o

hipmod-objs := preinput.o preoutput.o hip.o builder.o keymat.o unit.o test.o input.o output.o \
	       hidb.o hadb.o debug.o cookie.o workqueue.o misc.o dh.o \
               socket.o hashtable.o rvs.o update.o netlink.o xfrm.o beet.o \
               preinput.o preoutput.o

CRYPTOOBJS := mpi-bit.o mpi-div.o mpi-inline.o mpi-mpow.o mpi-pow.o \
mpicoder.o mpih-mul.o mpi-add.o mpi-cmp.o mpi-gcd.o mpi-inv.o \
mpi-mul.o mpi-scan.o mpih-div.o mpiutil.o kernel-interface.o \
dh.o dsa.o rsa.o

ASMFILES := mpih-add1.o mpih-lshift.o mpih-mul1.o mpih-mul2.o mpih-mul3.o
ASMFILES += mpih-rshift.o mpih-sub1.o

ifneq ($(SUBARCH),)
REALARCH := $(SUBARCH)
else
REALARCH := $(ARCH)
endif

hipmod-objs += $(addprefix crypto/, $(CRYPTOOBJS))
hipmod-objs += $(addprefix crypto/$(REALARCH)/, $(ASMFILES))

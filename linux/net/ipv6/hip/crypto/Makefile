# rocks
#

ASMFILES := mpih-add1.o mpih-lshift.o mpih-mul1.o mpih-mul2.o mpih-mul3.o
ASMFILES += mpih-rshift.o mpih-sub1.o

ifneq ($(SUBARCH),)
REALARCH := $(SUBARCH)
else
REALARCH := $(ARCH)
endif

#O_TARGET := cryptocode.o
obj-y += $(REALARCH)/ mpi-bit.o mpi-div.o mpi-inline.o mpi-mpow.o mpi-pow.o  
obj-y += mpicoder.o mpih-mul.o mpi-add.o mpi-cmp.o mpi-gcd.o mpi-inv.o
obj-y += mpi-mul.o mpi-scan.o mpih-div.o mpiutil.o kernel-interface.o
obj-y += dh.o dsa.o

# rocks
#

ASMFILES := mpih-add1.S mpih-lshift.S mpih-mul1.S mpih-mul2.S mpih-mul3.S
ASMFILES += mpih-rshift.S mpih-sub1.S

ifneq ($(SUBARCH),)
REALARCH := $(SUBARCH)
else
REALARCH := $(ARCH)
endif

#O_TARGET := cryptocode.o

obj-y := mpi-bit.o mpi-div.o mpi-inline.o mpi-mpow.o mpi-pow.o  
obj-y += mpicoder.o mpih-mul.o mpi-add.o mpi-cmp.o mpi-gcd.o mpi-inv.o
obj-y += mpi-mul.o mpi-scan.o mpih-div.o mpiutil.o kernel-interface.o
obj-y += dh.o dsa.o
obj-y += mpih-add1.o mpih-lshift.o mpih-mul1.o mpih-mul2.o mpih-mul3.o 
obj-y += mpih-rshift.o mpih-sub1.o

obj-m := $(O_TARGET)

$(ASMFILES): asm-syntax.h
	ln -s $(REALARCH)/$@ .

asm-syntax.h:
	ln -s $(REALARCH)/asm-syntax.h .


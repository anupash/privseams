obj-m += hipsock.o

KERNEL_SRC=/usr/src/linux

# Note: for some reason, setting up the CFLAGS as a variable does not work -mk

all:
	CFLAGS="-Wall -Wstrict-prototypes -O2 -fomit-frame-pointer  -Wno-trigraphs -fno-strict-aliasing -Wno-pointer-sign -Wdeclaration-after-statement -g" make -C $(KERNEL_SRC) M=$(PWD) modules
	gcc modtest.c -o modtest
          
clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean
	rm modtest

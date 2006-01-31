obj-m += hipsock.o

all:
	# make -C /lib/modules/$(shell uname -r)/kernel M=$(PWD) modules
	make -C /usr/src/linux M=$(PWD) modules
	gcc -Wall modtest.c -o modtest
          
clean:
	make -C /usr/src/linux M=$(PWD) clean
	rm modtest
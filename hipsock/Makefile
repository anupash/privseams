# This makefile assumes that your linux lernel sources
# are located in LUNUX_DIR (/usr/src/linux. If this is
# not the case please modify this Makefile or create a
# symbolic link to the actual location.

LINUX_DIR += /usr/src/linux
obj-m += hipsock.o



all:

	# make -C /lib/modules/$(shell uname -r)/kernel M=$(PWD) modules
	make -C $(LINUX_DIR) x M=$(PWD) modules
	gcc -Wall modtest.c -o modtest
          
clean:
	make -C $(LINUX_DIR) M=$(PWD) clean
	rm modtest
obj-m += hipsock.o debug.o

# Default assumption of the linux sources. Do not change! Use the
# command line option.
#
LINUX=/usr/src/linux

all: warn
	make -C $(LINUX) M=$(PWD) modules

warn:
	@echo ""
	@echo "##########################################################"
	@echo "# Default assumption of kernel sources in /usr/src/linux #"
	@echo "# Override with make LINUX=/path/to/linux/sources        #"
	@echo "##########################################################"
	@echo ""

clean:
	make -C $(LINUX) M=$(PWD) clean

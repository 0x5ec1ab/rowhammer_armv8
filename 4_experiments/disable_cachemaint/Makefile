obj-m += disable_cache_maint.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod disable_cache_maint.ko
	sudo rmmod disable_cache_maint.ko
	dmesg

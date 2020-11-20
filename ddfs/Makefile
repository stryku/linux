KERNELDIR = /lib/modules/`uname -r`/build
modules = ddfs.ko
obj-m += ddfs.o

all: 
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

insert:
	sudo insmod ddfs.ko

rmmod:
	sudo rmmod ddfs

install:
	make -C $(KERNELDIR) M=$(PWD) modules_install


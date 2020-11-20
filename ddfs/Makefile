KERNELDIR = ..
modules = ddfs.ko
obj-m += ddfs.o

all: 
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

install:
	make -C $(KERNELDIR) M=$(PWD) modules_install



obj-m+=novalkm.o

novalkm-objs := nova_main.o

all:
	    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean




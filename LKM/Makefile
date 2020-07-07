
modname=novalkm

obj-m+=$(modname).o

novalkm-objs := nova_main.o

all:
	    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean


add:
	sudo insmod $(modname).ko

remove:
	sudo rmmod $(modname)

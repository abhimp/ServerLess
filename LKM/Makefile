
modname=novalkm

obj-m+=$(modname).o

novalkm-objs := nova_main.o

.PHONY: clean all

all: nova_syscall.h
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

nova_syscall.h: parseCSV.py syscall.csv
	python3.7 parseCSV.py syscall.csv > nova_syscall.h

add:
	sudo insmod $(modname).ko

del:
	sudo rmmod $(modname)

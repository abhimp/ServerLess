
modname=novalkm

obj-m+=$(modname).o

novalkm-objs := nova_main.o nova_syscall.o

.PHONY: clean all

all: nova_syscall.h
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

nova_syscall.h: parseCSV.py syscall.csv
	python3.7 parseCSV.py syscall.csv

add:
	sudo insmod $(modname).ko

del:
	sudo rmmod $(modname)

enable:
	echo 1 > /proc/hello

disable:
	python3.7 -c 'open("/proc/hello", "wb").write(b"\0\0\0")'

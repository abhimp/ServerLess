
modname=novalkm

obj-m+=$(modname).o

novalkm-objs := nova_main.o nova_util.o

.PHONY: clean all

all: nova_syscall.h nova_controller
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	rm nova_controller || true
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

nova_syscall.h: parseCSV.py syscall.csv
	python3.7 parseCSV.py syscall.csv

nova_controller: nova_userland.c
	gcc -o nova_controller nova_userland.c

add:
	sudo insmod $(modname).ko

del:
	sudo rmmod $(modname)

enable:
	echo 1 > /proc/hello

disable:
	python3.7 -c 'open("/proc/hello", "wb").write(b"\0\0\0")'

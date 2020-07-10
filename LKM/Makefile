
modname=novalkm

obj-m+=$(modname).o

novalkm-objs := nova_main.o nova_util.o

.PHONY: clean all add del enable disable

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

enable: nova_userland
	./nova_userland enable


disable: nova_userland
	./nova_userland disable

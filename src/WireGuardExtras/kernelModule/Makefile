obj-m += wgchar.o

all:
	$(CC) testwgchar.c -o test
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm test

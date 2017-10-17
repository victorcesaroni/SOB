obj-m += cryptoSOB.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc device_test.c -o device_test

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm device_test


obj-m+=myModule.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	sleep 5
	gcc app_writer.c -o app_writer
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	sleep 5
	rm app_writer

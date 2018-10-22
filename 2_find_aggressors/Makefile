
all : librowhammer.so

librowhammer.so : pagemap.c
	gcc -fPIC -shared -o librowhammer.so pagemap.c

install : 
	sudo cp librowhammer.so /usr/local/lib/
	sudo cp pagemap.h /usr/local/include/
	sudo ldconfig

uninstall : 
	sudo rm /usr/local/lib/librowhammer.so
	sudo rm /usr/local/include/pagemap.h


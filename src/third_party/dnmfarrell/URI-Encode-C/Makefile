CC=gcc
CFLAGS=-Wall -O3 -std=gnu99
DESTDIR=/usr
PREFIX=/local
alib=liburi_encode.a

make:
	$(CC) $(CFLAGS) -c src/uri_encode.c -o uri_encode.o
	ar rcs liburi_encode.a uri_encode.o

test:
	$(CC) $(CFLAGS) src/main.c -Ilib -L. -luri_encode -o run-tests
	./run-tests
	rm run-tests

.PHONY: install
install: $(alib)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	mkdir -p $(DESTDIR)$(PREFIX)/include
	cp $(alib) $(DESTDIR)$(PREFIX)/lib/$(alib)
	cp src/uri_encode.h $(DESTDIR)$(PREFIX)/include/

clean:
	rm uri_encode.o liburi_encode.a

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(alib)
	rm -f $(DESTDIR)$(PREFIX)/include/uri_encode.h

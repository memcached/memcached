all: memcached memcached-debug

memcached: memcached.c slabs.c items.c memcached.h
	gcc-2.95  -I. -L. -static -o memcached memcached.c slabs.c items.c -levent -lJudy

memcached-debug: memcached.c slabs.c items.c memcached.h
	gcc-2.95 -g  -I. -L. -static -o memcached-debug memcached.c slabs.c items.c -levent -lJudy

clean:
	rm memcached memcached-debug

all: memcached

memcached: memcached.c slabs.c items.c memcached.h
	$(CC)  -I. -L. -static -o memcached memcached.c slabs.c items.c -levent -lJudy

memcached-debug: memcached.c slabs.c items.c memcached.h
	$(CC) -g  -I. -L. -static -o memcached-debug memcached.c slabs.c items.c -levent -lJudy

clean:
	rm memcached memcached-debug

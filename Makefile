all: memcached memcached-debug

memcached: memcached.c
	gcc-2.95  -I. -L. -static -o memcached memcached.c -levent -lJudy

memcached-debug: memcached.c
	gcc-2.95 -g  -I. -L. -static -o memcached-debug memcached.c -levent -lJudy

clean:
	rm memcached memcached-debug

bin_PROGRAMS = memcached

memcached_SOURCES = memcached.c slabs.c items.c memcached.h assoc.c
memcached_LDADD = @LIBOBJS@

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts TODO

AM_CFLAGS=-DNDEBUG


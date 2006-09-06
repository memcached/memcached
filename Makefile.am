bin_PROGRAMS = memcached memcached-debug

memcached_SOURCES = memcached.c slabs.c items.c assoc.c
memcached_debug_SOURCES = $(memcached_SOURCES)
memcached_CPPFLAGS = -DNDEBUG
memcached_LDADD = @LIBOBJS@
memcached_debug_LDADD = $(memcached_LDADD)

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts TODO t

memcached.c: memcached.h

test:	memcached-debug
	prove t

dist-hook:
	rm -rf $(distdir)/doc/.svn/
	rm -rf $(distdir)/scripts/.svn/
	rm -rf $(distdir)/t/.svn/
	rm -rf $(distdir)/t/lib/.svn/

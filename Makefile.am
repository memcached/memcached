bin_PROGRAMS = memcached

memcached_SOURCES = memcached.c slabs.c items.c memcached.h assoc.c
memcached_LDADD = @LIBOBJS@

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts TODO test

# FIXME: how to run Perl tests from automake?
#TESTS = test/getset.t

AM_CFLAGS=-DNDEBUG

dist-hook:
	rm -rf $(distdir)/doc/.svn/
	rm -rf $(distdir)/scripts/.svn/



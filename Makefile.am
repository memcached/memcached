bin_PROGRAMS = memcached

memcached_SOURCES = memcached.c slabs.c items.c memcached.h assoc.c
memcached_LDADD = @LIBOBJS@

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts TODO t

# FIXME: how to run Perl tests from automake?
#TESTS = test/getset.t

# Uncomment the following to save some CPU (by disabling assertions), at the risk of silent data
# structure corruption.  After all, this is a new branch of memcached, so you probably want
# assertions enabled.
#AM_CFLAGS=-DNDEBUG

dist-hook:
	rm -rf $(distdir)/doc/.svn/
	rm -rf $(distdir)/scripts/.svn/
	rm -rf $(distdir)/t/.svn/
	rm -rf $(distdir)/t/lib/.svn/

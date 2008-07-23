bin_PROGRAMS = memcached memcached-debug

memcached_SOURCES = memcached.c slabs.c slabs.h items.c items.h assoc.c assoc.h memcached.h thread.c stats.c stats.h
memcached_debug_SOURCES = $(memcached_SOURCES)
memcached_CPPFLAGS = -DNDEBUG
memcached_LDADD = @DTRACE_OBJ@ @DAEMON_OBJ@ 
memcached_debug_LDADD = @DTRACE_DEBUG_OBJ@ @DAEMON_OBJ@
memcached_DEPENDENCIES = @DTRACE_OBJ@ @DAEMON_OBJ@
memcached_debug_DEPENDENCIES = @DTRACE_DEBUG_OBJ@ @DAEMON_OBJ@

memcached_dtrace.h:
	${DTRACE} -h -s memcached_dtrace.d 
	sed -e s,_DTRACE_VERSION,ENABLE_DTRACE,g memcached_dtrace.h | \
            tr '\t' ' ' | grep -v unistd.h > memcached_dtrace.tmp
	mv memcached_dtrace.tmp memcached_dtrace.h

memcached_dtrace.o: $(memcached_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o memcached_dtrace.o -s ${srcdir}/memcached_dtrace.d $(memcached_OBJECTS)

memcached_debug_dtrace.o: $(memcached_debug_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o memcached_debug_dtrace.o -s ${srcdir}/memcached_dtrace.d $(memcached_debug_OBJECTS)

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts TODO t memcached.spec

test:	memcached-debug
	prove $(srcdir)/t

dist-hook:
	rm -rf $(distdir)/doc/.svn/
	rm -rf $(distdir)/scripts/.svn/
	rm -rf $(distdir)/t/.svn/
	rm -rf $(distdir)/t/lib/.svn/

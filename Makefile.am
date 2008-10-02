bin_PROGRAMS = memcached memcached-debug
pkginclude_HEADERS = protocol_binary.h

BUILT_SOURCES= @DTRACE_HEADER@

memcached_SOURCES = memcached.c slabs.c slabs.h items.c items.h assoc.c assoc.h memcached.h thread.c stats.c stats.h
memcached_debug_SOURCES = $(memcached_SOURCES)
memcached_CPPFLAGS = -DNDEBUG
memcached_LDADD = @DTRACE_OBJ@ @DAEMON_OBJ@ 
memcached_debug_LDADD = @DTRACE_DEBUG_OBJ@ @DAEMON_OBJ@
memcached_DEPENDENCIES = @DTRACE_OBJ@ @DAEMON_OBJ@
memcached_debug_DEPENDENCIES = @DTRACE_DEBUG_OBJ@ @DAEMON_OBJ@

memcached_dtrace.h: memcached_dtrace.d
	${DTRACE} -h -s memcached_dtrace.d 
	sed -e 's,void \*,const void \*,g' memcached_dtrace.h | \
            sed -e 's,char \*,const char \*,g' | tr '\t' ' ' > mmc_dtrace.tmp
	mv mmc_dtrace.tmp memcached_dtrace.h

memcached_dtrace.o: $(memcached_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o memcached_dtrace.o -s ${srcdir}/memcached_dtrace.d $(memcached_OBJECTS)

memcached_debug_dtrace.o: $(memcached_debug_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o memcached_debug_dtrace.o -s ${srcdir}/memcached_dtrace.d $(memcached_debug_OBJECTS)

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts TODO t memcached.spec daemon.c memcached_dtrace.d

test:	memcached-debug
	prove $(srcdir)/t

dist-hook:
	rm -rf $(distdir)/doc/.svn/
	rm -rf $(distdir)/scripts/.svn/
	rm -rf $(distdir)/t/.svn/
	rm -rf $(distdir)/t/lib/.svn/

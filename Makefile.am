bin_PROGRAMS = memcached
pkginclude_HEADERS = protocol_binary.h
noinst_PROGRAMS = memcached-debug sizes testapp timedrun

BUILT_SOURCES=

testapp_SOURCES = testapp.c util.c util.h

timedrun_SOURCES = timedrun.c

memcached_SOURCES = memcached.c memcached.h \
                    hash.c hash.h \
                    jenkins_hash.c jenkins_hash.h \
                    murmur3_hash.c murmur3_hash.h \
                    slabs.c slabs.h \
                    items.c items.h \
                    assoc.c assoc.h \
                    thread.c daemon.c \
                    stats.c stats.h \
                    util.c util.h \
                    trace.h cache.h sasl_defs.h \
                    bipbuffer.c bipbuffer.h \
                    logger.c logger.h \
                    crawler.c crawler.h \
                    itoa_ljust.c itoa_ljust.h \
                    slab_automove.c slab_automove.h

if BUILD_CACHE
memcached_SOURCES += cache.c
testapp_SOURCES += cache.c
endif

if BUILD_SOLARIS_PRIVS
memcached_SOURCES += solaris_priv.c
endif

if BUILD_LINUX_PRIVS
memcached_SOURCES += linux_priv.c
endif

if BUILD_OPENBSD_PRIVS
memcached_SOURCES += openbsd_priv.c
endif

if ENABLE_SASL
memcached_SOURCES += sasl_defs.c
endif

if ENABLE_EXTSTORE
memcached_SOURCES += extstore.c extstore.h \
                     crc32c.c crc32c.h \
                     storage.c storage.h \
                     slab_automove_extstore.c slab_automove_extstore.h
endif

memcached_debug_SOURCES = $(memcached_SOURCES)
memcached_CPPFLAGS = -DNDEBUG
memcached_debug_LDADD = @PROFILER_LDFLAGS@
memcached_debug_CFLAGS = @PROFILER_FLAGS@

memcached_LDADD =
memcached_DEPENDENCIES =
memcached_debug_DEPENDENCIES =
CLEANFILES=

if BUILD_LINUX_PRIVS
memcached_LDADD += -lseccomp
memcached_debug_LDADD += -lseccomp
endif

if BUILD_DTRACE
BUILT_SOURCES += memcached_dtrace.h
CLEANFILES += memcached_dtrace.h
endif

if DTRACE_INSTRUMENT_OBJ
memcached_LDADD += memcached_dtrace.o
memcached_DEPENDENCIES += memcached_dtrace.o
memcached_debug_LDADD += memcached_debug_dtrace.o
memcached_debug_DEPENDENCIES += memcached_debug_dtrace.o
CLEANFILES += memcached_dtrace.o memcached_debug_dtrace.o
endif

memcached_debug_CFLAGS += -DMEMCACHED_DEBUG

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
EXTRA_DIST = doc scripts t memcached.spec memcached_dtrace.d version.m4 README.md LICENSE.bipbuffer

MOSTLYCLEANFILES = *.gcov *.gcno *.gcda *.tcov

test:	memcached-debug sizes testapp
	$(srcdir)/sizes
	$(srcdir)/testapp
	@if test -n "${PARALLEL}"; then \
	  prove $(srcdir)/t -j ${PARALLEL}; \
	else \
	  prove $(srcdir)/t; \
	fi
	@if test `basename $(PROFILER)` = "gcov"; then \
	  for file in memcached_debug-*.gc??; do \
	    mv -f $$file `echo $$file | sed 's/memcached_debug-//'`; \
	  done && \
	  for file in *.gcda; do \
	    srcfile=`echo $$file | sed 's/.gcda/.c/'`; \
	    if test -n "`echo $(memcached_debug_SOURCES) | grep $$srcfile`"; then \
	      echo `$(PROFILER) $$srcfile` | sed 's/'$$srcfile':.*//'; \
	    fi \
	  done \
	elif test `basename $(PROFILER)` = "tcov"; then \
	  files=`grep SRCFILE memcached-debug.profile/tcovd | sed 's/SRCFILE://' | sort | uniq` && \
	  $(PROFILER) -x memcached-debug.profile $$files 2>&1; \
	  for file in *.tcov; do \
	    srcfile=`echo $$file | sed 's/.tcov//'`; \
	    if test -n "`echo $(memcached_debug_SOURCES) | grep $$srcfile`"; then \
	      echo $$srcfile : `grep 'Percent of the file executed' $$file`; \
	    fi \
	  done \
	else :; fi

docs:
	(cat Doxyfile ; echo "PROJECT_NUMBER=`cat version.num`") | doxygen -

dist-hook:
	rm -f $(distdir)/*/*~ $(distdir)/t/lib/*~ $(distdir)/*~

maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm config.guess
	-rm config.sub
	-rm depcomp
	-rm install-sh
	-rm ltmain.sh
	-rm missing
	-rm configure
	-rm config.log
	-rm config.status

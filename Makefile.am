bin_PROGRAMS = memcached
pkginclude_HEADERS = include/memcached/protocol_binary.h \
                     include/memcached/engine.h \
                     include/memcached/config_parser.h

noinst_PROGRAMS = sizes testapp timedrun

BUILT_SOURCES=

testapp_SOURCES = testapp.c

testapp_DEPENDENCIES= libconfig.la libutil.la
testapp_LDADD= libconfig.la libutil.la

timedrun_SOURCES = timedrun.c

memcached_SOURCES = memcached.c memcached.h \
                    hash.c hash.h \
                    thread.c daemon.c \
                    stats.c stats.h \
                    trace.h cache.h sasl_defs.h \
					stdin_check.c

noinst_LTLIBRARIES= libconfig.la libutil.la
libconfig_la_SOURCES= config_parser.c
libutil_la_SOURCES= util.c util.h

if BUILD_CACHE
memcached_SOURCES += cache.c
testapp_SOURCES += cache.c
endif

if BUILD_SOLARIS_PRIVS
memcached_SOURCES += solaris_priv.c
endif

if ENABLE_SASL
memcached_SOURCES += sasl_defs.c
endif

memcached_LDADD = libconfig.la libutil.la @PROFILER_LDFLAGS@
memcached_LDFLAGS =-R '$(libdir)'
memcached_CFLAGS = @PROFILER_FLAGS@
memcached_DEPENDENCIES = libconfig.la libutil.la
CLEANFILES=


if BUILD_DTRACE
BUILT_SOURCES += memcached_dtrace.h
CLEANFILES += memcached_dtrace.h
endif

if DTRACE_INSTRUMENT_OBJ
memcached_LDADD += memcached_dtrace.o
memcached_DEPENDENCIES += memcached_dtrace.o
CLEANFILES += memcached_dtrace.o
endif

lib_LTLIBRARIES = default_engine.la
default_engine_la_SOURCES= \
                    assoc.c assoc.h \
                    default_engine.c default_engine.h \
                    items.c items.h \
                    slabs.c slabs.h

default_engine_la_DEPENDENCIES= libutil.la
default_engine_la_LIBADD=  libutil.la
default_engine_la_LDFLAGS= -module -dynamic

if INCLUDE_DEFAULT_ENGINE
memcached_SOURCES += $(default_engine_la_SOURCES)
endif

memcached_dtrace.h: memcached_dtrace.d
	${DTRACE} -h -s memcached_dtrace.d
	sed -e 's,void \*,const void \*,g' memcached_dtrace.h | \
            sed -e 's,char \*,const char \*,g' | tr '\t' ' ' > mmc_dtrace.tmp
	mv mmc_dtrace.tmp memcached_dtrace.h

memcached_dtrace.o: $(memcached_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o memcached_dtrace.o -s ${srcdir}/memcached_dtrace.d $(memcached_OBJECTS)

SUBDIRS = doc
DIST_DIRS = scripts
EXTRA_DIST = doc scripts t memcached.spec memcached_dtrace.d m4/version.m4

MOSTLYCLEANFILES = *.gcov *.gcno *.gcda *.tcov

test:	memcached sizes testapp
	./sizes
	./testapp
	prove $(srcdir)/t
	@if test `basename $(PROFILER)` = "gcov"; then \
	  for file in memcached-*.gc??; do \
	    mv -f $$file `echo $$file | sed 's/memcached-//'`; \
	  done && \
	  for file in *.gcda; do \
	    srcfile=`echo $$file | sed 's/.gcda/.c/'`; \
	    if test -n "`echo $(memcached_SOURCES) | grep $$srcfile`"; then \
	      echo `$(PROFILER) $$srcfile` | sed 's/'$$srcfile':.*//'; \
	    fi \
	  done \
	elif test `basename $(PROFILER)` = "tcov"; then \
	  files=`grep SRCFILE memcached.profile/tcovd | sed 's/SRCFILE://' | sort | uniq` && \
	  $(PROFILER) -x memcached.profile $$files 2>&1; \
	  for file in *.tcov; do \
	    srcfile=`echo $$file | sed 's/.tcov//'`; \
	    if test -n "`echo $(memcached_SOURCES) | grep $$srcfile`"; then \
	      echo $$srcfile : `grep 'Percent of the file executed' $$file`; \
	    fi \
	  done \
	else :; fi

docs:
	${DOXYGEN} config/Doxyfile-api
	${DOXYGEN} config/Doxyfile

dist-hook:
	rm -f $(distdir)/*/*~ $(distdir)/t/lib/*~ $(distdir)/*~

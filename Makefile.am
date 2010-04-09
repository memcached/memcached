bin_PROGRAMS = memcached
pkginclude_HEADERS = include/memcached/protocol_binary.h \
                     include/memcached/callback.h \
                     include/memcached/engine.h \
                     include/memcached/extension.h \
                     include/memcached/server_api.h \
                     include/memcached/config_parser.h \
                     include/memcached/util.h \
                     include/memcached/genhash.h

noinst_PROGRAMS = sizes testapp timedrun

BUILT_SOURCES=

testapp_SOURCES = testapp.c

testapp_DEPENDENCIES= libmcd_util.la
testapp_LDADD= libmcd_util.la

timedrun_SOURCES = timedrun.c

memcached_SOURCES = memcached.c memcached.h \
                    hash.c hash.h \
                    thread.c daemon.c \
                    stats.c stats.h \
                    trace.h cache.h sasl_defs.h \
                    topkeys.c topkeys.h

libmcd_util_la_SOURCES= config_parser.c include/memcached/config_parser.h \
                        util.c include/memcached/util.h \
                        genhash.c genhash_int.h \
                        include/memcached/genhash.h
libmcd_util_la_LDFLAGS= -dynamic

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

memcached_LDADD = @PROFILER_LDFLAGS@

if ENABLE_ISASL
memcached_SOURCES += sasl_defs.c isasl.c
endif

memcached_LDFLAGS =-R '$(libdir)'
memcached_CFLAGS = @PROFILER_FLAGS@
memcached_DEPENDENCIES =

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

noinst_LTLIBRARIES = libmcd_util.la
lib_LTLIBRARIES = default_engine.la \
                  stdin_term_handler.la


default_engine_la_SOURCES= \
                    assoc.c assoc.h \
                    default_engine.c default_engine.h \
                    items.c items.h \
                    slabs.c slabs.h

default_engine_la_SOURCES += $(libmcd_util_la_SOURCES)
default_engine_la_DEPENDENCIES=
default_engine_la_LIBADD=
default_engine_la_LDFLAGS= -module -dynamic


stdin_term_handler_la_SOURCES= stdin_check.c stdin_check.h
stdin_term_handler_la_SOURCES += $(libmcd_util_la_SOURCES)
stdin_term_handler_la_DEPENDENCIES=
stdin_term_handler_la_LIBADD=
stdin_term_handler_la_LDFLAGS= -module -dynamic


if INCLUDE_DEFAULT_ENGINE
memcached_SOURCES += $(default_engine_la_SOURCES)
endif

memcached_SOURCES += $(libmcd_util_la_SOURCES)

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

test:	memcached sizes testapp timedrun
	./sizes
	./testapp
	prove $(srcdir)/t
	@if test -n "$(PROFILER)"; then \
	  if test `basename $(PROFILER)` = "gcov"; then \
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
	  else :; fi \
	else :; fi

docs:
	${DOXYGEN} config/Doxyfile-api
	${DOXYGEN} config/Doxyfile

dist-hook:
	rm -f $(distdir)/*/*~ $(distdir)/t/lib/*~ $(distdir)/*~

# Please list files alphabetically in the lists to reduce the risk for
# a merge conflict.
#
bin_PROGRAMS = engine_testapp memcached
noinst_PROGRAMS = sizes testapp timedrun
pkginclude_HEADERS = \
                     include/memcached/callback.h \
                     include/memcached/config_parser.h \
                     include/memcached/engine.h \
                     include/memcached/engine_common.h \
                     include/memcached/engine_testapp.h \
                     include/memcached/extension.h \
                     include/memcached/extension_loggers.h \
                     include/memcached/genhash.h \
                     include/memcached/mock_server.h \
                     include/memcached/protocol_binary.h \
                     include/memcached/protocol_plugin.h \
                     include/memcached/server_api.h \
                     include/memcached/types.h \
                     include/memcached/util.h \
                     include/memcached/vbucket.h \
                     include/memcached/visibility.h

lib_LTLIBRARIES = ascii_scrub.la \
                  basic_engine_testsuite.la \
                  default_engine.la \
                  example_protocol.la \
                  stdin_term_handler.la

if BUILD_SYSLOG_LOGGER
lib_LTLIBRARIES += syslog_logger.la
endif

noinst_LTLIBRARIES=libmcd_util.la


# Test application to test stuff from C
testapp_SOURCES = testapp.c
testapp_DEPENDENCIES= libmcd_util.la
testapp_LDADD= libmcd_util.la $(APPLICATION_LIBS)

# New and fancy test program to test engines without the need to run
# everything through the network layer
engine_testapp_SOURCES = \
                        engine_testapp.c \
                        include/memcached/engine_testapp.h
engine_testapp_DEPENDENCIES= libmcd_util.la
engine_testapp_LDADD= libmcd_util.la $(APPLICATION_LIBS)

# Small application used start another application and terminate it after
# a certain amount of time
timedrun_SOURCES = timedrun.c

# A collection of functions used by the various modules in memcached
libmcd_util_la_SOURCES= \
                        config_parser.c \
                        engine_loader.h engine_loader.c \
                        extension_loggers.c \
                        genhash.c \
                        genhash_int.h \
                        include/memcached/config_parser.h \
                        include/memcached/genhash.h \
                        include/memcached/util.h \
                        mock_server.c \
                        util.c

memcached_SOURCES = \
                    cache.h \
                    config_static.h \
                    daemon.c \
                    hash.c \
                    hash.h \
                    memcached.c\
                    memcached.h \
                    sasl_defs.h \
                    stats.c stats.h \
                    thread.c \
                    topkeys.c \
                    topkeys.h \
                    trace.h
memcached_LDFLAGS =-R '$(libdir)'
memcached_CFLAGS = @PROFILER_FLAGS@
memcached_DEPENDENCIES = libmcd_util.la
memcached_LDADD = @PROFILER_LDFLAGS@ libmcd_util.la -levent $(APPLICATION_LIBS)

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

if ENABLE_ISASL
memcached_SOURCES += sasl_defs.c isasl.c isasl.h
endif

if INCLUDE_DEFAULT_ENGINE
memcached_SOURCES += $(default_engine_la_SOURCES)
memcached_LDFLAGS += -export-dynamic
endif

CLEANFILES=
BUILT_SOURCES=

# The default storage engine
default_engine_la_SOURCES= \
                    assoc.c \
                    assoc.h \
                    default_engine.c \
                    default_engine.h \
                    items.c \
                    items.h \
                    slabs.c \
                    slabs.h
default_engine_la_DEPENDENCIES= libmcd_util.la
default_engine_la_LIBADD= libmcd_util.la $(LIBM)
default_engine_la_LDFLAGS= -avoid-version -shared -module -no-undefined

if BUILD_DTRACE
BUILT_SOURCES += memcached_dtrace.h
CLEANFILES += memcached_dtrace.h
endif

if DTRACE_INSTRUMENT_OBJ
memcached_LDADD += memcached_dtrace.o
memcached_DEPENDENCIES += memcached_dtrace.o
CLEANFILES += memcached_dtrace.o default_engine_dtrace.lo

default_engine_la_LIBADD += default_engine_dtrace.lo
default_engine_la_DEPENDENCIES += default_engine_dtrace.lo
endif

# ASCII support for the scrub command
ascii_scrub_la_SOURCES= ascii_scrub.c protocol_extension.h
ascii_scrub_la_LDFLAGS= -avoid-version -shared -module -no-undefined

# An extension that will shut down memcached if standard input is closed
stdin_term_handler_la_SOURCES= stdin_check.c stdin_check.h
stdin_term_handler_la_LDFLAGS= -avoid-version -shared -module -no-undefined

# An example extension that extends the ascii protocol with noop and echo
example_protocol_la_SOURCES= example_protocol.c protocol_extension.h
example_protocol_la_LDFLAGS= -avoid-version -shared -module -no-undefined

# A logger using syslog
syslog_logger_la_SOURCES = syslog_logger.c
syslog_logger_la_LDFLAGS = -avoid-version -shared -module -no-undefined

basic_engine_testsuite_la_SOURCES= basic_engine_testsuite.c
basic_engine_testsuite_la_DEPENDENCIES= libmcd_util.la
basic_engine_testsuite_la_LIBADD= libmcd_util.la $(LIBM)
basic_engine_testsuite_la_LDFLAGS= -avoid-version -shared -module -no-undefined

memcached_dtrace.h: memcached_dtrace.d
	${DTRACE} -h -s $(top_srcdir)/memcached_dtrace.d
	sed -e 's,void \*,const void \*,g' memcached_dtrace.h | \
            sed -e 's,char \*,const char \*,g' | tr '\t' ' ' > mmc_dtrace.tmp
	mv mmc_dtrace.tmp memcached_dtrace.h

memcached_dtrace.o: $(memcached_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o memcached_dtrace.o -s ${srcdir}/memcached_dtrace.d $(memcached_OBJECTS)

# We don't have real libtool support for dtrace (at least I
# don't know how that works), so instead I just copy the
# .lo file from assoc.lo and replace all references to assoc.x with
# default_engine_dtrace.x
DEFAULT_ENGINE_OBJS=$(default_engine_la_OBJECTS:%lo=.libs/%o)
default_engine_dtrace.lo: $(default_engine_la_OBJECTS)
	$(DTRACE) $(DTRACEFLAGS) -G -o .libs/default_engine_dtrace.o -s ${srcdir}/memcached_dtrace.d $(DEFAULT_ENGINE_OBJS)
	sed -e s,assoc,default_engine_dtrace,g assoc.lo > default_engine_dtrace.lo

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

# Please list files alphabetically in the lists to reduce the risk for
# a merge conflict.
#
man_MANS = doc/memcached.1
bin_PROGRAMS = engine_testapp memcached mcstat
noinst_PROGRAMS = sizes testapp timedrun
pkginclude_HEADERS = \
                     include/memcached/callback.h \
                     include/memcached/config_parser.h \
                     include/memcached/engine.h \
                     include/memcached/engine_common.h \
                     include/memcached/engine_testapp.h \
                     include/memcached/extension.h \
                     include/memcached/extension_loggers.h \
                     include/memcached/protocol_binary.h \
                     include/memcached/protocol_plugin.h \
                     include/memcached/server_api.h \
                     include/memcached/types.h \
                     include/memcached/util.h \
                     include/memcached/vbucket.h \
                     include/memcached/visibility.h

# libmemcached_utilities.la needs to be listed first because some of the
# other modules depend on it
pkglib_LTLIBRARIES = libmemcached_utilities.la \
                     ascii_scrub.la \
                     basic_engine_testsuite.la \
                     default_engine.la \
                     example_protocol.la \
                     fragment_rw_ops.la \
                     blackhole_logger.la \
                     stdin_term_handler.la

if BUILD_SYSLOG_LOGGER
pkglib_LTLIBRARIES += syslog_logger.la
endif

if BUILD_EVENTLOG_LOGGER
pkglib_LTLIBRARIES += eventlog_logger.la
endif

noinst_LTLIBRARIES=

sizes_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/daemon
sizes_SOURCES = programs/sizes.c


# Test application to test stuff from C
testapp_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/daemon
testapp_SOURCES = programs/testapp.c
testapp_DEPENDENCIES= libmemcached_utilities.la
testapp_LDADD= libmemcached_utilities.la $(APPLICATION_LIBS)

mcstat_SOURCES = programs/mcstat.c
mcstat_LDADD = $(APPLICATION_LIBS)


# New and fancy test program to test engines without the need to run
# everything through the network layer
engine_testapp_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/programs
engine_testapp_SOURCES = \
                        programs/engine_testapp.c \
                        programs/mock_server.c \
                        programs/mock_server.h \
                        include/memcached/engine_testapp.h
engine_testapp_DEPENDENCIES= libmemcached_utilities.la
engine_testapp_LDADD= libmemcached_utilities.la $(APPLICATION_LIBS)

# Small application used start another application and terminate it after
# a certain amount of time
timedrun_SOURCES = programs/timedrun.c

# A collection of functions used by the various modules in memcached
libmemcached_utilities_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/utilities
libmemcached_utilities_la_LDFLAGS =-R '$(pkglibdir)' -R '$(libdir)'
libmemcached_utilities_la_SOURCES= \
                        include/memcached/config_parser.h \
                        include/memcached/util.h \
                        utilities/config_parser.c \
                        utilities/engine_loader.c \
                        utilities/engine_loader.h \
                        utilities/extension_loggers.c \
                        utilities/util.c

memcached_SOURCES = \
                    daemon/cache.h \
                    config_static.h \
                    daemon/daemon.c \
                    daemon/hash.c \
                    daemon/hash.h \
                    daemon/memcached.c\
                    daemon/memcached.h \
                    daemon/sasl_defs.h \
                    daemon/stats.c \
                    daemon/stats.h \
                    daemon/thread.c \
                    trace.h
memcached_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/daemon
memcached_LDFLAGS =-R '$(pkglibdir)' -R '$(libdir)'
memcached_CFLAGS = @PROFILER_FLAGS@
memcached_DEPENDENCIES = libmemcached_utilities.la
memcached_LDADD = @PROFILER_LDFLAGS@ libmemcached_utilities.la -levent $(APPLICATION_LIBS)

if EMBEDDED_LIBEVENT
libevent.stamp:
	(cd $(top_srcdir)/libevent && make)
	touch libevent.stamp

libmemcached_utilities_la_DEPENDENCIES = libevent.stamp
endif

if BUILD_CACHE
memcached_SOURCES += daemon/cache.c
testapp_SOURCES += daemon/cache.c
endif

if BUILD_SOLARIS_PRIVS
memcached_SOURCES += daemon/solaris_priv.c
endif

if ENABLE_SASL
memcached_SOURCES += daemon/sasl_defs.c
endif

if ENABLE_ISASL
memcached_SOURCES += daemon/sasl_defs.c daemon/isasl.c daemon/isasl.h
endif

if INCLUDE_DEFAULT_ENGINE
memcached_SOURCES += $(default_engine_la_SOURCES)
memcached_LDFLAGS += -export-dynamic
endif

CLEANFILES=
BUILT_SOURCES=

# The default storage engine
default_engine_la_SOURCES= engines/default_engine/assoc.c \
                           engines/default_engine/assoc.h \
                           engines/default_engine/default_engine.c \
                           engines/default_engine/default_engine.h \
                           engines/default_engine/items.c \
                           engines/default_engine/items.h \
                           engines/default_engine/slabs.c \
                           engines/default_engine/slabs.h

default_engine_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/engines/default_engine
default_engine_la_DEPENDENCIES= libmemcached_utilities.la
default_engine_la_LIBADD= libmemcached_utilities.la $(LIBM)
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
ascii_scrub_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
ascii_scrub_la_SOURCES= extensions/protocol/ascii_scrub.c \
                        extensions/protocol_extension.h
ascii_scrub_la_LDFLAGS= -avoid-version -shared -module -no-undefined

# An extension that supports partital read/write operation
fragment_rw_ops_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
fragment_rw_ops_la_SOURCES = extensions/protocol/fragment_rw.c
fragment_rw_ops_la_LDFLAGS = -avoid-version -shared -module -no-undefined
fragment_rw_ops_la_LIBADD = libmemcached_utilities.la $(LIBM)
fragment_rw_ops_la_DEPENDENCIES = libmemcached_utilities.la

# An extension that will shut down memcached if standard input is closed
stdin_term_handler_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
stdin_term_handler_la_SOURCES= extensions/daemon/stdin_check.c \
                               extensions/protocol_extension.h
stdin_term_handler_la_LDFLAGS= -avoid-version -shared -module -no-undefined

# An example extension that extends the ascii protocol with noop and echo
example_protocol_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
example_protocol_la_SOURCES= extensions/protocol/example_protocol.c \
                             extensions/protocol_extension.h
example_protocol_la_LDFLAGS= -avoid-version -shared -module -no-undefined

# A logger just ignoring the output
blackhole_logger_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
blackhole_logger_la_SOURCES = extensions/loggers/blackhole_logger.c \
                              extensions/protocol_extension.h
blackhole_logger_la_LDFLAGS = -avoid-version -shared -module -no-undefined

# A logger using syslog
syslog_logger_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
syslog_logger_la_SOURCES = extensions/loggers/syslog_logger.c \
                           extensions/protocol_extension.h
syslog_logger_la_LDFLAGS = -avoid-version -shared -module -no-undefined

# A logger using eventlog
eventlog_logger_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/extensions
eventlog_logger_la_SOURCES = extensions/loggers/eventlog_logger.c \
                             extensions/protocol_extension.h
eventlog_logger_la_LDFLAGS = -avoid-version -shared -module -no-undefined


basic_engine_testsuite_la_SOURCES= testsuite/basic_engine_testsuite.c \
                                   testsuite/basic_engine_testsuite.h
basic_engine_testsuite_la_DEPENDENCIES= libmemcached_utilities.la
basic_engine_testsuite_la_LIBADD= libmemcached_utilities.la $(LIBM)
basic_engine_testsuite_la_LDFLAGS= -avoid-version -shared -module -no-undefined

breakdancer_testsuite_la_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir)/testsuite/breakdancer
breakdancer_testsuite_la_SOURCES= breakdancer_testsuite.c \
                                  testsuite/breakdancer/suite_stubs.c \
                                  testsuite/breakdancer/suite_stubs.h
breakdancer_testsuite_la_LDFLAGS= -avoid-version -shared -module -no-undefined -rpath /nowhere

breakdancer_testsuite.c: testsuite/breakdancer/breakdancer.py testsuite/breakdancer/engine_test.py
	${top_srcdir}/testsuite/breakdancer/engine_test.py > breakdancer_testsuite.c || ( rm breakdancer_testsuite.c && /bin/false)

ENGINE_TESTS=test_engine

if ENABLE_BREAKDANCE
noinst_LTLIBRARIES += breakdancer_testsuite.la
BUILT_SOURCES += breakdancer_testsuite.c
CLEANFILES += breakdancer_testsuite.c
ENGINE_TESTS += breakdancer_engine
endif

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
	$(DTRACE) $(DTRACEFLAGS) -G -o .libs/default_engine_la-default_engine_dtrace.o -s ${srcdir}/memcached_dtrace.d $(DEFAULT_ENGINE_OBJS)
	sed -e s,assoc,default_engine_dtrace,g default_engine_la-assoc.lo > default_engine_dtrace.lo

DIST_DIRS = scripts
EXTRA_DIST = doc scripts t memcached.spec memcached_dtrace.d m4/version.m4 \
             testsuite/breakdancer/engine_test.py testsuite/breakdancer/breakdancer.py \
             LICENSE CONTRIBUTING HACKING win32

MOSTLYCLEANFILES = *.gcov *.gcno *.gcda *.tcov

TEST_TIMEOUT=30

breakdancer_engine: engine_testapp breakdancer_testsuite.la
	./engine_testapp -. -q -E .libs/default_engine.so -t $(TEST_TIMEOUT) \
		-T .libs/breakdancer_testsuite.so

test_engine: engine_testapp basic_engine_testsuite.la
	./engine_testapp -E .libs/default_engine.so -t $(TEST_TIMEOUT) \
		-T .libs/basic_engine_testsuite.so

test: $(bin_PROGRAMS) $(noinst_PROGRAMS) $(pkglib_LTLIBRARIES) $(ENGINE_TESTS)
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

LE_VERSION=1.4.14b-stable
LE_FN=libevent-$(LE_VERSION).tar.gz
LE_URL=http://monkey.org/~provos/$(LE_FN)

$(srcdir)/$(LE_FN):
	wget $(LE_URL) || curl -O $(LE_URL)

dist-hook: $(srcdir)/$(LE_FN)
	rm -rf $(distdir)/libevent*
	gzip -dc $(srcdir)/$(LE_FN) | (cd $(distdir) && tar xf -)
	mv $(distdir)/libevent-$(LE_VERSION) $(distdir)/libevent
	rm -f $(distdir)/*/*~ $(distdir)/t/lib/*~ $(distdir)/*~

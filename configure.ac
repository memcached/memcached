AC_PREREQ(2.52)
AC_INIT(memcached, 1.1.0, brad@danga.com)
AC_CONFIG_SRCDIR(memcached.c)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_INSTALL

dnl Default to building a static executable.
AC_ARG_ENABLE(static,
	AC_HELP_STRING([--disable-static],[build a dynamically linked executable]),
	, enable_static=yes)
AC_MSG_CHECKING(whether to build a static executable)
if test "$enable_static" = "no"; then
	STATIC=
	AC_MSG_RESULT(no)
else
	CFLAGS="$CFLAGS -static"
	AC_MSG_RESULT(yes)
fi

LIBEVENT_URL=http://www.monkey.org/~provos/libevent/
AC_CHECK_LIB(event, event_set, ,
	[AC_MSG_ERROR(libevent is required.  You can get it from $LIBEVENT_URL)])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

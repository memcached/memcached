AC_PREREQ(2.52)
AC_INIT(memcached, 1.1.13-pre, brad@danga.com)
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR(memcached.c)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_INSTALL

AC_ARG_WITH(libevent,
	AC_HELP_STRING([--with-libevent=DIRECTORY],[base directory for libevent]))
if test "$with_libevent" != "no"; then
	CFLAGS="$CFLAGS -I$with_libevent/include"
	LDFLAGS="$LDFLAGS -L$with_libevent/lib"
fi

LIBEVENT_URL=http://www.monkey.org/~provos/libevent/
AC_CHECK_LIB(event, event_set, ,
	[AC_MSG_ERROR(libevent is required.  You can get it from $LIBEVENT_URL)])

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(mallinfo, malloc)

AC_CHECK_FUNC(daemon,AC_DEFINE([HAVE_DAEMON],,[Define this if you have daemon()]),[AC_LIBOBJ(daemon)])


AC_CHECK_HEADER(malloc.h, AC_DEFINE(HAVE_MALLOC_H,,[do we have malloc.h?]))
AC_CHECK_MEMBER([struct mallinfo.arena], [
		AC_DEFINE(HAVE_STRUCT_MALLINFO,,[do we have stuct mallinfo?])
	], ,[
#	include <malloc.h>
	]
)

dnl From licq: Copyright (c) 2000 Dirk Mueller
dnl Check if the type socklen_t is defined anywhere
AC_DEFUN(AC_C_SOCKLEN_T,
[AC_CACHE_CHECK(for socklen_t, ac_cv_c_socklen_t,
[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/socket.h>
  ],[
    socklen_t foo;
  ],[
    ac_cv_c_socklen_t=yes
  ],[
    ac_cv_c_socklen_t=no
  ])
])
if test $ac_cv_c_socklen_t = no; then
  AC_DEFINE(socklen_t, int, [define to int if socklen_t not available])
fi
])

AC_C_SOCKLEN_T

AC_CHECK_FUNCS(mlockall)

AC_CONFIG_FILES(Makefile doc/Makefile)
AC_OUTPUT

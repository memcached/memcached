AC_PREREQ(2.52)
AC_INIT(memcached, 1.1.10pre, brad@danga.com)
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

dnl Default to building a static executable.
AC_ARG_ENABLE(static,
	AC_HELP_STRING([--disable-static],[build a dynamically linked executable]),
	, enable_static=yes)
AC_MSG_CHECKING(whether to build a static executable)

dnl Darwin can't do static binaries
case "$host" in
  *-darwin*)
    enable_static=no
    ;;
  *)
  ;;
esac

if test "$enable_static" = "no"; then
	STATIC=
	AC_MSG_RESULT(no)
else
	CFLAGS="$CFLAGS -static"
	AC_MSG_RESULT(yes)
fi

AC_CHECK_FUNCS(mlockall)

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

AC_PREREQ(2.52)
m4_include([version.m4])
m4_include([m4/c99-backport.m4])
AC_INIT(memcached, VERSION_NUMBER, memcached@googlegroups.com)
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR(memcached.c)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC

dnl **********************************************************************
dnl DETECT_ICC ([ACTION-IF-YES], [ACTION-IF-NO])
dnl
dnl check if this is the Intel ICC compiler, and if so run the ACTION-IF-YES
dnl sets the $ICC variable to "yes" or "no"
dnl **********************************************************************
AC_DEFUN([DETECT_ICC],
[
    ICC="no"
    AC_MSG_CHECKING([for icc in use])
    if test "$GCC" = "yes"; then
       dnl check if this is icc acting as gcc in disguise
       AC_EGREP_CPP([^__INTEL_COMPILER], [__INTEL_COMPILER],
         AC_MSG_RESULT([no])
         [$2],
         AC_MSG_RESULT([yes])
         [$1]
         ICC="yes")
    else
       AC_MSG_RESULT([no])
       [$2]
    fi
])

DETECT_ICC([], [])

dnl **********************************************************************
dnl DETECT_CLANG ([ACTION-IF-YES], [ACTION-IF-NO])
dnl
dnl check if compiler is clang, and if so run the ACTION-IF-YES sets the
dnl $CLANG variable to "yes" or "no"
dnl **********************************************************************
AC_DEFUN([DETECT_CLANG],
[
    AC_MSG_CHECKING([for clang in use])
    AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([], [[
    #ifndef __clang__
           not clang
    #endif
    ]])],
    [CLANG=yes], [CLANG=no])
    AC_MSG_RESULT([$CLANG])
    AS_IF([test "$CLANG" = "yes"],[$1],[$2])
])
DETECT_CLANG([],[])

dnl **********************************************************************
dnl DETECT_SUNCC ([ACTION-IF-YES], [ACTION-IF-NO])
dnl
dnl check if this is the Sun Studio compiler, and if so run the ACTION-IF-YES
dnl sets the $SUNCC variable to "yes" or "no"
dnl **********************************************************************
AC_DEFUN([DETECT_SUNCC],
[
    AC_CHECK_DECL([__SUNPRO_C], [SUNCC="yes"], [SUNCC="no"])
    AS_IF(test "x$SUNCC" = "xyes", [$1], [$2])

])

DETECT_SUNCC([CFLAGS="-mt $CFLAGS"], [])
AS_IF([test "$ICC" = "yes" -o "$GCC" = "yes"],
[
    AS_IF(test "$CLANG" = "no",[CFLAGS="$CFLAGS -pthread"])
])

if test "$ICC" = "no"; then
   AC_PROG_CC_C99
fi

AM_PROG_CC_C_O
AC_PROG_INSTALL

AC_ARG_ENABLE(sasl,
  [AS_HELP_STRING([--enable-sasl],[Enable SASL authentication])])

AC_ARG_ENABLE(sasl_pwdb,
  [AS_HELP_STRING([--enable-sasl-pwdb],[Enable plaintext password db])])

AS_IF([test "x$enable_sasl_pwdb" = "xyes"],
      [enable_sasl=yes ])



dnl **********************************************************************
dnl DETECT_SASL_CB_GETCONF
dnl
dnl check if we can use SASL_CB_GETCONF
dnl **********************************************************************
AC_DEFUN([AC_C_DETECT_SASL_CB_GETCONF],
[
    AC_CACHE_CHECK([for SASL_CB_GETCONF],
        [ac_cv_c_sasl_cb_getconf],
        [AC_TRY_COMPILE(
            [
#include <sasl/sasl.h>
            ], [
unsigned long val = SASL_CB_GETCONF;
            ],
            [ ac_cv_c_sasl_cb_getconf=yes ],
            [ ac_cv_c_sasl_cb_getconf=no ])
        ])
    AS_IF([test "$ac_cv_c_sasl_cb_getconf" = "yes"],
          [AC_DEFINE([HAVE_SASL_CB_GETCONF], 1,
                     [Set to nonzero if your SASL implementation supports SASL_CB_GETCONF])])
])

AC_CHECK_HEADERS([sasl/sasl.h])
if test "x$enable_sasl" = "xyes"; then
  AC_C_DETECT_SASL_CB_GETCONF
  AC_DEFINE([ENABLE_SASL],1,[Set to nonzero if you want to include SASL])
  AC_SEARCH_LIBS([sasl_server_init], [sasl2 sasl], [],
    [
      AC_MSG_ERROR([Failed to locate the library containing sasl_server_init])
    ])

  AS_IF([test "x$enable_sasl_pwdb" = "xyes"],
        [AC_DEFINE([ENABLE_SASL_PWDB], 1,
                   [Set to nonzero if you want to enable a SASL pwdb])])
fi

AC_ARG_ENABLE(dtrace,
  [AS_HELP_STRING([--enable-dtrace],[Enable dtrace probes])])
if test "x$enable_dtrace" = "xyes"; then
  AC_PATH_PROG([DTRACE], [dtrace], "no", [/usr/sbin:$PATH])
  if test "x$DTRACE" != "xno"; then
    AC_DEFINE([ENABLE_DTRACE],1,[Set to nonzero if you want to include DTRACE])
    build_dtrace=yes
    # DTrace on MacOSX does not use -G option
    $DTRACE -G -o conftest.$$ -s memcached_dtrace.d 2>/dev/zero
    if test $? -eq 0
    then
        dtrace_instrument_obj=yes
        rm conftest.$$
    fi

    if test "`which tr`" = "/usr/ucb/tr"; then
        AC_MSG_ERROR([Please remove /usr/ucb from your path. See man standards for more info])
    fi
  else
    AC_MSG_ERROR([Need dtrace binary and OS support.])
  fi
fi

AM_CONDITIONAL([BUILD_DTRACE],[test "$build_dtrace" = "yes"])
AM_CONDITIONAL([DTRACE_INSTRUMENT_OBJ],[test "$dtrace_instrument_obj" = "yes"])
AM_CONDITIONAL([ENABLE_SASL],[test "$enable_sasl" = "yes"])

AC_SUBST(DTRACE)
AC_SUBST(DTRACEFLAGS)
AC_SUBST(ENABLE_SASL)
AC_SUBST(PROFILER_LDFLAGS)

AC_ARG_ENABLE(coverage,
  [AS_HELP_STRING([--disable-coverage],[Disable code coverage])])

if test "x$enable_coverage" != "xno"; then
   if test "$GCC" = "yes" -a "$ICC" != "yes" -a "$CLANG" != "yes"
   then
      CFLAGS="$CFLAGS -pthread"
      AC_PATH_PROG([PROFILER], [gcov], "no", [$PATH])
      if test "x$PROFILER" != "xno"; then
         # Issue 97: The existense of gcov doesn't mean we have -lgcov
         AC_CHECK_LIB(gcov, main,
                    [
                      PROFILER_FLAGS="-fprofile-arcs -ftest-coverage"
                      PROFILER_LDFLAGS="-lgcov"
                    ], [
                      PROFILER_FLAGS=
                      PROFILER_LDFLAGS=
                    ])
      fi
   elif test "$SUNCC" = "yes"
   then
      AC_PATH_PROG([PROFILER], [tcov], "no", [$PATH])
      if test "x$PROFILER" != "xno"; then
         PROFILER_FLAGS=-xprofile=tcov
      fi
   elif test "x$CLANG" != "xno"
   then
      AC_PATH_PROG([PROFILER], [gcov], "no", [$PATH])
      if test "x$PROFILER" != "xno"
      then
          PROFILER_FLAGS="-fprofile-arcs -ftest-coverage"
          PROFILER_LDFLAGS=
      fi
   fi
fi
AC_SUBST(PROFILER_FLAGS)


AC_ARG_ENABLE(64bit,
  [AS_HELP_STRING([--enable-64bit],[build 64bit version])])
if test "x$enable_64bit" = "xyes"
then
    org_cflags=$CFLAGS
    CFLAGS=-m64
    AC_RUN_IFELSE(
      [AC_LANG_PROGRAM([], [dnl
return sizeof(void*) == 8 ? 0 : 1;
      ])
    ],[
      CFLAGS="-m64 $org_cflags"
    ],[
    AC_MSG_ERROR([Don't know how to build a 64-bit object.])
    ])
fi

# Issue 213: Search for clock_gettime to help people linking
#            with a static version of libevent
AC_SEARCH_LIBS(clock_gettime, rt)
# Issue 214: Search for the network libraries _before_ searching
#            for libevent (to help people linking with static libevent)
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)

trylibeventdir=""
AC_ARG_WITH(libevent,
       [  --with-libevent=PATH     Specify path to libevent installation ],
       [
                if test "x$withval" != "xno" ; then
                        trylibeventdir=$withval
                fi
       ]
)

dnl ------------------------------------------------------
dnl libevent detection.  swiped from Tor.  modified a bit.

LIBEVENT_URL=http://www.monkey.org/~provos/libevent/

AC_CACHE_CHECK([for libevent directory], ac_cv_libevent_dir, [
  saved_LIBS="$LIBS"
  saved_LDFLAGS="$LDFLAGS"
  saved_CPPFLAGS="$CPPFLAGS"
  le_found=no
  for ledir in $trylibeventdir "" $prefix /usr/local ; do
    LDFLAGS="$saved_LDFLAGS"
    LIBS="-levent $saved_LIBS"

    # Skip the directory if it isn't there.
    if test ! -z "$ledir" -a ! -d "$ledir" ; then
       continue;
    fi
    if test ! -z "$ledir" ; then
      if test -d "$ledir/lib" ; then
        LDFLAGS="-L$ledir/lib $LDFLAGS"
      else
        LDFLAGS="-L$ledir $LDFLAGS"
      fi
      if test -d "$ledir/include" ; then
        CPPFLAGS="-I$ledir/include $CPPFLAGS"
      else
        CPPFLAGS="-I$ledir $CPPFLAGS"
      fi
    fi
    # Can I compile and link it?
    AC_TRY_LINK([#include <sys/time.h>
#include <sys/types.h>
#include <event.h>], [ event_init(); ],
       [ libevent_linked=yes ], [ libevent_linked=no ])
    if test $libevent_linked = yes; then
       if test ! -z "$ledir" ; then
         ac_cv_libevent_dir=$ledir
         _myos=`echo $target_os | cut -f 1 -d .`
         AS_IF(test "$SUNCC" = "yes" -o "x$_myos" = "xsolaris2",
               [saved_LDFLAGS="$saved_LDFLAGS -Wl,-R$ledir/lib"],
               [AS_IF(test "$GCC" = "yes",
                     [saved_LDFLAGS="$saved_LDFLAGS -Wl,-rpath,$ledir/lib"])])
       else
         ac_cv_libevent_dir="(system)"
       fi
       le_found=yes
       break
    fi
  done
  LIBS="$saved_LIBS"
  LDFLAGS="$saved_LDFLAGS"
  CPPFLAGS="$saved_CPPFLAGS"
  if test $le_found = no ; then
    AC_MSG_ERROR([libevent is required.  You can get it from $LIBEVENT_URL

      If it's already installed, specify its path using --with-libevent=/dir/
])
  fi
])
LIBS="-levent $LIBS"
if test $ac_cv_libevent_dir != "(system)"; then
  if test -d "$ac_cv_libevent_dir/lib" ; then
    LDFLAGS="-L$ac_cv_libevent_dir/lib $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir/lib"
  else
    LDFLAGS="-L$ac_cv_libevent_dir $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir"
  fi
  if test -d "$ac_cv_libevent_dir/include" ; then
    CPPFLAGS="-I$ac_cv_libevent_dir/include $CPPFLAGS"
  else
    CPPFLAGS="-I$ac_cv_libevent_dir $CPPFLAGS"
  fi
fi

dnl ----------------------------------------------------------------------------

AC_SEARCH_LIBS(umem_cache_create, umem)
AC_SEARCH_LIBS(gethugepagesizes, hugetlbfs)

AC_HEADER_STDBOOL
AH_BOTTOM([#if HAVE_STDBOOL_H
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif ])

AC_CHECK_HEADERS([inttypes.h])
AH_BOTTOM([#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
])

dnl **********************************************************************
dnl Figure out if this system has the stupid sasl_callback_ft
dnl **********************************************************************

AC_DEFUN([AC_HAVE_SASL_CALLBACK_FT],
[AC_CACHE_CHECK(for sasl_callback_ft, ac_cv_has_sasl_callback_ft,
[
  AC_TRY_COMPILE([
    #ifdef HAVE_SASL_SASL_H
    #include <sasl/sasl.h>
    #include <sasl/saslplug.h>
    #endif
  ],[
    sasl_callback_ft a_callback;
  ],[
    ac_cv_has_sasl_callback_ft=yes
  ],[
    ac_cv_has_sasl_callback_ft=no
  ])
])
if test $ac_cv_has_sasl_callback_ft = yes; then
  AC_DEFINE(HAVE_SASL_CALLBACK_FT, 1, [we have sasl_callback_ft])
fi
])

AC_HAVE_SASL_CALLBACK_FT

dnl **********************************************************************
dnl DETECT_UINT64_SUPPORT
dnl
dnl check if we can use a uint64_t
dnl **********************************************************************
AC_DEFUN([AC_C_DETECT_UINT64_SUPPORT],
[
    AC_CACHE_CHECK([for print macros for integers (C99 section 7.8.1)],
        [ac_cv_c_uint64_support],
        [AC_TRY_COMPILE(
            [
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <stdio.h>
            ], [
  uint64_t val = 0;
  fprintf(stderr, "%" PRIu64 "\n", val);
            ],
            [ ac_cv_c_uint64_support=yes ],
            [ ac_cv_c_uint64_support=no ])
        ])
])

AC_C_DETECT_UINT64_SUPPORT
AS_IF([test "x$ac_cv_c_uint64_support" = "xno"],
      [AC_MSG_WARN([

Failed to use print macros (PRIu) as defined in C99 section 7.8.1.

])])

AC_C_CONST

dnl From licq: Copyright (c) 2000 Dirk Mueller
dnl Check if the type socklen_t is defined anywhere
AC_DEFUN([AC_C_SOCKLEN_T],
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

dnl Check if we're a little-endian or a big-endian system, needed by hash code
AC_DEFUN([AC_C_ENDIAN],
[AC_CACHE_CHECK(for endianness, ac_cv_c_endian,
[
  AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([], [dnl
        long val = 1;
        char *c = (char *) &val;
        exit(*c == 1);
    ])
  ],[
    ac_cv_c_endian=big
  ],[
    ac_cv_c_endian=little
  ])
])
if test $ac_cv_c_endian = big; then
  AC_DEFINE(ENDIAN_BIG, 1, [machine is bigendian])
fi
if test $ac_cv_c_endian = little; then
  AC_DEFINE(ENDIAN_LITTLE, 1, [machine is littleendian])
fi
])

AC_C_ENDIAN

AC_DEFUN([AC_C_HTONLL],
[
    AC_MSG_CHECKING([for htonll])
    have_htoll="no"
    AC_TRY_LINK([
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h> */
#endif
       ], [
          return htonll(0);
       ], [
          have_htoll="yes"
          AC_DEFINE([HAVE_HTONLL], [1], [Have ntohll])
    ], [
          have_htoll="no"
    ])

    AC_MSG_RESULT([$have_htoll])
])

AC_C_HTONLL

dnl Check whether the user's system supports pthread
AC_SEARCH_LIBS(pthread_create, pthread)
if test "x$ac_cv_search_pthread_create" = "xno"; then
  AC_MSG_ERROR([Can't enable threads without the POSIX thread library.])
fi

AC_CHECK_FUNCS(mlockall)
AC_CHECK_FUNCS(getpagesizes)
AC_CHECK_FUNCS(memcntl)
AC_CHECK_FUNCS(sigignore)
AC_CHECK_FUNCS(clock_gettime)
AC_CHECK_FUNCS([accept4], [AC_DEFINE(HAVE_ACCEPT4, 1, [Define to 1 if support accept4])])

AC_DEFUN([AC_C_ALIGNMENT],
[AC_CACHE_CHECK(for alignment, ac_cv_c_alignment,
[
  AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([
#include <stdlib.h>
#include <inttypes.h>
    ], [
       char *buf = malloc(32);

       uint64_t *ptr = (uint64_t*)(buf+2);
       // catch sigbus, etc.
       *ptr = 0x1;

       // catch unaligned word access (ARM cpus)
#ifdef ENDIAN_BIG
#define ALIGNMENT 0x02030405
#else
#define ALIGNMENT 0x05040302
#endif
       *(buf + 0) = 1;
       *(buf + 1) = 2;
       *(buf + 2) = 3;
       *(buf + 3) = 4;
       *(buf + 4) = 5;
       int* i = (int*)(buf+1);
       return (ALIGNMENT == *i) ? 0 : 1;
    ])
  ],[
    ac_cv_c_alignment=none
  ],[
    ac_cv_c_alignment=need
  ],[
    ac_cv_c_alignment=need
  ])
])
if test $ac_cv_c_alignment = need; then
  AC_DEFINE(NEED_ALIGN, 1, [Machine need alignment])
fi
])

AC_C_ALIGNMENT

dnl Check for our specific usage of GCC atomics.
dnl These were added in 4.1.2, but 32bit OS's may lack shorts and 4.1.2
dnl lacks testable defines.
have_gcc_atomics=no
AC_MSG_CHECKING(for GCC atomics)
AC_TRY_LINK([],[
  unsigned short a;
  unsigned short b;
  b = __sync_add_and_fetch(&a, 1);
  b = __sync_sub_and_fetch(&a, 2);
  ],[have_gcc_atomics=yes
  AC_DEFINE(HAVE_GCC_ATOMICS, 1, [GCC Atomics available])])
AC_MSG_RESULT($have_gcc_atomics)

dnl Check for the requirements for running memcached with less privileges
dnl than the default privilege set. On Solaris we need setppriv and priv.h
dnl If you want to add support for other platforms you should check for
dnl your requirements, define HAVE_DROP_PRIVILEGES, and make sure you add
dnl the source file containing the implementation into memcached_SOURCE
dnl in Makefile.am
AC_CHECK_FUNCS(setppriv, [
   AC_CHECK_HEADER(priv.h, [
      AC_DEFINE([HAVE_DROP_PRIVILEGES], 1,
         [Define this if you have an implementation of drop_privileges()])
      build_solaris_privs=yes
   ], [])
],[])

AM_CONDITIONAL([BUILD_SOLARIS_PRIVS],[test "$build_solaris_privs" = "yes"])

AC_CHECK_HEADER(umem.h, [
   AC_DEFINE([HAVE_UMEM_H], 1,
         [Define this if you have umem.h])
   build_cache=no
], [build_cache=yes])

AM_CONDITIONAL([BUILD_CACHE], [test "x$build_cache" = "xyes"])

AC_ARG_ENABLE(docs,
  [AS_HELP_STRING([--disable-docs],[Disable documentation generation])])

AC_PATH_PROG([XML2RFC], [xml2rfc], "no")
AC_PATH_PROG([XSLTPROC], [xsltproc], "no")

AM_CONDITIONAL([BUILD_SPECIFICATIONS],
               [test "x$enable_docs" != "xno" -a "x$XML2RFC" != "xno" -a "x$XSLTPROC" != "xno"])


dnl Let the compiler be a bit more picky. Please note that you cannot
dnl specify these flags to the compiler before AC_CHECK_FUNCS, because
dnl the test program will generate a compilation warning and hence fail
dnl to detect the function ;-)
if test "$ICC" = "yes"
then
   dnl ICC trying to be gcc.
   CFLAGS="$CFLAGS -diag-disable 187 -Wall -Werror"
   AC_DEFINE([_GNU_SOURCE],[1],[find sigignore on Linux])
elif test "$GCC" = "yes"
then
  GCC_VERSION=`$CC -dumpversion`
  CFLAGS="$CFLAGS -Wall -Werror -pedantic -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls"
  case $GCC_VERSION in
    4.4.*)
    CFLAGS="$CFLAGS -fno-strict-aliasing"
    ;;
  esac
  AC_DEFINE([_GNU_SOURCE],[1],[find sigignore on Linux])
elif test "$SUNCC" = "yes"
then
  CFLAGS="$CFLAGS -errfmt=error -errwarn -errshort=tags"
fi

AC_CONFIG_FILES(Makefile doc/Makefile)
AC_OUTPUT

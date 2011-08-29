AC_PREREQ(2.60)
m4_include([m4/version.m4])
m4_include([m4/c99-backport.m4])
m4_include([m4/libevent.m4])
AC_INIT(memcached, VERSION_NUMBER, memcached@googlegroups.com)
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR(Makefile.am)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

if test "x${enable_dependency_tracking}" = "x"
then
  enable_dependency_tracking=yes
fi

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

AS_IF(test "x$GCC" = "xyes",
      DETECT_ICC([CFLAGS="-pthread $CFLAGS"], [CFLAGS="-fvisibility=hidden -pthread $CFLAGS"]),
      ICC=no
      DETECT_SUNCC([CFLAGS="-xldscope=hidden -mt -xc99=all $CFLAGS"], []))

if test "$ICC" = "no"; then
   AC_PROG_CC_C99
fi

AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_C_BIGENDIAN

AC_ARG_ENABLE([bundled-libevent],
  [AS_HELP_STRING([--enable-bundled-libevent],
          [Build with the bundled libevent. @<:@default=on@:>@])],
    [ac_cv_bundled_libevent="$enableval"],
    [ac_cv_bundled_libevent="yes"])
AC_ARG_ENABLE(sasl,
  [AS_HELP_STRING([--enable-sasl],[Enable SASL authentication])])
AC_ARG_ENABLE(isasl,
  [AS_HELP_STRING([--enable-isasl],[Enable internal SASL implementation])])

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

AC_CHECK_HEADERS_ONCE(link.h dlfcn.h inttypes.h umem.h priv.h sasl/sasl.h sysexits.h sys/wait.h sys/socket.h netinet/in.h netdb.h unistd.h sys/un.h sys/stat.h sys/resource.h sys/uio.h netinet/tcp.h pwd.h sys/mman.h syslog.h windows.h)

AM_CONDITIONAL(BUILD_SYSLOG_LOGGER, test "x$ac_cv_header_syslog_h" = "xyes")
AM_CONDITIONAL(BUILD_EVENTLOG_LOGGER, test "x$ac_cv_header_windows_h" = "xyes")

if test "x$enable_isasl" = "xyes"; then
  AC_DEFINE([ENABLE_ISASL],1,[Set to nonzero if you want to include ISASL])
  ac_cv_saslpasswd2="isasl"
  if test "x$enable_sasl" = "xyes"; then
      AC_MSG_ERROR([You can't specify isasl and sasl at the same time])
  fi
elif test "x$enable_sasl" = "xyes"; then
  AC_PATH_PROG(ac_cv_saslpasswd2, saslpasswd2, ,/usr/sbin:/usr/bin:/usr/local/bin:/usr/opt/bin/:/opt/bin)
  AC_C_DETECT_SASL_CB_GETCONF
  AC_DEFINE([ENABLE_SASL],1,[Set to nonzero if you want to include SASL])
  AC_SEARCH_LIBS([sasl_server_init], [sasl2 sasl], [],
    [
      AC_MSG_ERROR([Failed to locate the library containing sasl_server_init])
    ])

  AS_IF([test "x$enable_sasl_pwdb" = "xyes"],
        [AC_DEFINE([ENABLE_SASL_PWDB], 1,
                   [Set to nonzero if you want to enable a SASL pwdb])])
  # test user supplied saslpasswd2 path - if supplied, or try to locate
  AC_ARG_WITH(saslpasswd2,
       [  --with-saslpasswd2=PATH  Specify location of saslpasswd2 binary],
       [
                if test "x$withval" != "xno" ; then
                  if test ! -x $withval ; then
                    AC_MSG_ERROR([The filename and/or path supplied to saslpasswd2 is wrong!])
                  else
                    ac_cv_saslpasswd2=$withval
                  fi
                fi
       ]
  )

  AC_CACHE_CHECK([for saslpasswd2 binary location], ac_cv_saslpasswd2, [
    if test -z "$ac_cv_saslpasswd2"; then
      AC_MSG_ERROR([saslpasswd2 is required if sasl is enabled.

      If it's already installed, specify its path using --with-saslpasswd=/full/path/saslpasswd2
      ])
    fi
  ])
fi
# even though the test won't run if no sasl, still need to generate
SASLPASSWD2=$ac_cv_saslpasswd2
AC_SUBST(SASLPASSWD2)
AC_CONFIG_FILES(t/binary-sasl.t)

AC_ARG_ENABLE(default-engine,
  [AS_HELP_STRING([--enable-default-engine], [Build-in default engine])])
AM_CONDITIONAL([INCLUDE_DEFAULT_ENGINE],[test "$enable_default_engine" = "yes"])

AC_ARG_ENABLE(dtrace,
  [AS_HELP_STRING([--enable-dtrace],[Enable dtrace probes])])
if test "x$enable_dtrace" = "xyes"; then
  AC_PATH_PROG([DTRACE], [dtrace], "no", [/usr/sbin:$PATH])
  if test "x$DTRACE" != "xno"; then
    AC_DEFINE([ENABLE_DTRACE],1,[Set to nonzero if you want to include DTRACE])
    build_dtrace=yes
    # DTrace on MacOSX does not use -G option
    cat > provider.$$.d <<EOF
provider autoconf {
  probe foo();
};
EOF
    $DTRACE -G -o conftest.$$ -s provider.$$.d 2>/dev/zero
    if test $? -eq 0
    then
        dtrace_instrument_obj=yes
        rm conftest.$$
    fi
    rm provider.$$.d

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
AM_CONDITIONAL([ENABLE_ISASL],[test "$enable_isasl" = "yes"])

AC_SUBST(DTRACE)
AC_SUBST(DTRACEFLAGS)
AC_SUBST(ENABLE_SASL)
AC_SUBST(ENABLE_ISASL)
AC_SUBST(PROFILER_LDFLAGS)

AC_ARG_ENABLE(coverage,
  [AS_HELP_STRING([--enable-coverage],[Disable code coverage])])

if test "x$enable_coverage" = "xyes"; then
   if test "$ICC" = "yes"
   then
      AC_MSG_WARN([icc doesn't support code coverage checking])
   elif test "$GCC" = "yes"
   then
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
embedded_libevent=no
AS_IF([test "x$ac_cv_bundled_libevent" = "xno"],
      [
         AC_LIBEVENT
      ], [
         AC_MSG_CHECKING([for bundled libevent])
         AS_IF([test -d ${srcdir}/libevent], [bundled_libevent=yes], [bundled_libevent=no])
         AC_MSG_RESULT([$bundled_libevent])

         AS_IF(test "x$bundled_libevent" = "xyes",
            [
                (cd $srcdir/libevent && ./configure --disable-shared)
                CPPFLAGS="-I$srcdir/libevent $CPPFLAGS"
                LDFLAGS="-L$srcdir/libevent/.libs $LDFLAGS"
                embedded_libevent=yes
           ],
           [
                AC_LIBEVENT
           ])
     ])

AM_CONDITIONAL([EMBEDDED_LIBEVENT],[test "$embedded_libevent" = "yes"])

dnl ----------------------------------------------------------------------------

dnl **********************************************************************
dnl AC_CHECK_LIBRARY ([symbol], [library])
dnl
dnl Check to see if we got the symbol in the given library, and push
dnl the library as $LIB(library)
dnl **********************************************************************
AC_DEFUN([AC_CHECK_LIBRARY],
[
   pushdef([NAME],[translit([$2],[abcdefghijklmnopqrstuvwxyz./-],
                                [ABCDEFGHIJKLMNOPQRSTUVWXYZ___])])
   saved_LIBS="$LIBS"
   LIBS=""
   AC_SEARCH_LIBS($1, $2)
   LIB[]NAME="$LIBS"
   LIBS="$saved_LIBS"
   AC_SUBST([LIB]NAME)
])

AC_CHECK_LIBRARY(umem_cache_create, umem)
AC_CHECK_LIBRARY(gethugepagesizes, hugetlbfs)
AC_CHECK_LIBRARY(dlopen, dl)
AC_CHECK_LIBRARY(log, m)
APPLICATION_LIBS="$LIBUMEM $LIBHUGETLBFS $LIBDL $LIBM"
AC_SUBST(APPLICATION_LIBS)

AC_HEADER_STDBOOL
AH_TOP([#ifndef CONFIG_H
#define CONFIG_H])
AH_BOTTOM([#include "config_static.h"
#endif])

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
       *buf =  1; *(buf +1) = 2; *(buf + 2) = 2; *(buf + 3) = 3; *(buf + 4) = 4;
       int* i = (int*)(buf+1);
       return (84148994 == i) ? 0 : 1;
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

dnl Check for the requirements for running memcached with less privileges
dnl than the default privilege set. On Solaris we need setppriv and priv.h
dnl If you want to add support for other platforms you should check for
dnl your requirements, define HAVE_DROP_PRIVILEGES, and make sure you add
dnl the source file containing the implementation into memcached_SOURCE
dnl in Makefile.am
AC_CHECK_FUNCS(setppriv, [
   AS_IF([test "x$ac_cv_header_priv_h" = "xyes" ], [
      AC_DEFINE([HAVE_DROP_PRIVILEGES], 1,
         [Define this if you have an implementation of drop_privileges()])
      build_solaris_privs=yes
   ])
],[])

AM_CONDITIONAL([BUILD_SOLARIS_PRIVS],[test "$build_solaris_privs" = "yes"])

AS_IF([ test "x$ac_cv_header_umem_h" = "xyes" ], [
   AC_DEFINE([HAVE_UMEM_H], 1,
         [Define this if you have umem.h])
   build_cache=no
], [build_cache=yes])

AM_CONDITIONAL([BUILD_CACHE], [test "x$build_cache" = "xyes"])

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
  AC_CHECK_DECL([__linux], [ AC_DEFINE([_GNU_SOURCE],[1],[find sigignore on Linux]) ])
  CFLAGS="$CFLAGS -errfmt=error -errwarn -errshort=tags"
fi

dnl Check for stuff needed to run Doxygen
AC_PATH_PROG([DOT], [dot], "no")
AS_IF(test "x$DOT" = "xno", [HAVE_DOT=NO], [HAVE_DOT=YES])
AC_PATH_PROG([DOXYGEN], [doxygen], "doxygen")
AC_PATH_PROG([PERL], [perl], "perl")
AC_SUBST(HAVE_DOT)
PROJECT_NUMBER=VERSION_NUMBER
AC_SUBST(PROJECT_NUMBER)

dnl Check if we can run breakdance
AC_PATH_PROG([PYTHON], [python], [no])
AC_ARG_ENABLE([breakdancer],
  [AS_HELP_STRING([--enable-breakdancer],
          [Build breakdancer tests. @<:@default=off@:>@])],
  [ac_cv_enable_breakdancer="$enableval"],
  [ac_cv_enable_breakdancer="no"])

AM_CONDITIONAL(ENABLE_BREAKDANCE,
               test "x$ac_cv_enable_breakdancer" = "xyes" -a "x$PYTHON" != "xno")

dnl Generate output files
CPPFLAGS="-I\${top_srcdir}/include ${CPPFLAGS}"
AC_CONFIG_FILES(Makefile config/Doxyfile config/Doxyfile-api)
AC_OUTPUT

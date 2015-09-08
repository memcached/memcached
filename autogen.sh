#!/bin/sh

# Get the initial version.
perl version.pl

die() {
    echo "$@"
    exit 1
}

# Try to locate a program by using which, and verify that the file is an
# executable
locate_binary() {
  for f in $@
  do
    file=`which $f 2>/dev/null | grep -v '^no '`
    if test -n "$file" -a -x "$file"; then
      echo $file
      return 0
    fi
  done

  echo ""
  return 1
}

echo "aclocal..."
if test x$ACLOCAL = x; then
  ACLOCAL=`locate_binary aclocal-1.14 aclocal-1.13 aclocal-1.12 aclocal-1.11 aclocal-1.10 aclocal-1.9 aclocal19 aclocal-1.7 aclocal17 aclocal-1.5 aclocal15 aclocal`
  if test x$ACLOCAL = x; then
    die "Did not find a supported aclocal"
  fi
fi
$ACLOCAL || exit 1

echo "autoheader..."
AUTOHEADER=${AUTOHEADER:-autoheader}
$AUTOHEADER || exit 1

echo "automake..."
if test x$AUTOMAKE = x; then
  AUTOMAKE=`locate_binary automake-1.15 automake-1.14 automake-1.13 automake-1.12 automake-1.11 automake-1.10 automake-1.9 automake-1.7`
  if test x$AUTOMAKE = x; then
    die "Did not find a supported automake"
  fi
fi
$AUTOMAKE --foreign --add-missing || $AUTOMAKE --gnu --add-missing || exit 1

echo "autoconf..."
AUTOCONF=${AUTOCONF:-autoconf}
$AUTOCONF || exit 1


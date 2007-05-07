#!/bin/sh
#
# This is hacky, because there are so many damn versions
# of autoconf/automake.  It works with Debian woody, at least.
#
# Debian sarge:
#    apt-get install automake1.7 autoconf
#

echo "aclocal..."
ACLOCAL=`which aclocal-1.9 || which aclocal19 || which aclocal-1.7 || which aclocal17 || which aclocal-1.5 || which aclocal15 || which aclocal || exit 1`
$ACLOCAL || exit 1

echo "autoheader..."
AUTOHEADER=${AUTOHEADER:-autoheader}
$AUTOHEADER || exit 1

echo "automake..."
AUTOMAKE=${AUTOMAKE:-automake-1.7}
$AUTOMAKE --foreign --add-missing || automake --gnu --add-missing || exit 1

echo "autoconf..."
AUTOCONF=${AUTOCONF:-autoconf}
$AUTOCONF || exit 1


#!/bin/sh

echo "aclocal..."
ACLOCAL=${ACLOCAL:-aclocal-1.7}
$ACLOCAL || exit 1

echo "autoheader..."
AUTOHEADER=${AUTOHEADER:-autoheader}
$AUTOHEADER || exit 1

echo "automake..."
AUTOMAKE=${AUTOMAKE:-automake-1.7}
$AUTOMAKE --gnu --add-missing || exit 1

echo "autoconf..."
AUTOCONF=${AUTOCONF:-autoconf}
$AUTOCONF || exit 1


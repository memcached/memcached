#!/bin/sh
GITHASH="44a55dee1d41c3ae92524df9f0dd8a747db79f04"
SHA="8d79b8f096c68ed827743dfded55981f1c7f297d"
FILE="${GITHASH}.tar.gz"

if ! command -v shasum >/dev/null 2>&1; then
    echo "missing command: shasum"
    exit 1
fi

if [ ! -f "$FILE" ]; then
    wget https://github.com/memcached/memcached-vendor/archive/$FILE
fi

hash=$(shasum "$FILE" | awk '{print $1}')
if [ "$SHA" = "$hash" ]; then
    tar -zxf ./$FILE --strip-components=1
    rm $FILE
else
    echo "vendor file hash did not match"
    exit 1
fi

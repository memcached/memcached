#!/bin/sh
GITHASH="726411c595ef64b4bd3a8bd7d72a49116c508d92"
SHA="f07f23eef030fa60fa5e24fb8a88ac15b1bbb4d3"
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

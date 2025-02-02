#!/bin/sh
GITHASH="fc32e928f0f42343634cfa153924b83a16a296f8"
SHA="2bb01940f556955dc663d739f88d99c094a2cbfe"
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

#!/bin/sh
HASH="44a55dee1d41c3ae92524df9f0dd8a747db79f04"
wget https://github.com/memcached/memcached-vendor/archive/${HASH}.tar.gz 
tar -zxf ./${HASH}.tar.gz --strip-components=1
rm ${HASH}.tar.gz

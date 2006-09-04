#!/usr/bin/perl

use strict;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $expire;

print $sock "set foo 0 1 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
print $sock "flush_all\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");

mem_get_is($sock, "foo", undef);
sleep 2;
mem_get_is($sock, "foo", undef);


#!/usr/bin/env perl

use strict;
use Test::More tests => 4;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached();
my $sock = $server->sock;

# set foo (and should get it)
print $sock "set foo 0 2 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "fooval");

# touch it
print $sock "touch foo 10\r\n";
is(scalar <$sock>, "TOUCHED\r\n", "touched foo");

sleep 2;
mem_get_is($sock, "foo", "fooval");

#!/usr/bin/perl

use strict;
use Test::More tests => 5;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

print $sock "set foo 123 1 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

print $sock "get foo\n";
is(scalar <$sock>, "VALUE foo 123 6\r\n", "got FOO value");
is(scalar <$sock>, "fooval\r\n", "got fooval");
is(scalar <$sock>, "END\r\n", "got END");
sleep(1.2);
print $sock "get foo\n";
is(scalar <$sock>, "END\r\n", "got END (no value)");








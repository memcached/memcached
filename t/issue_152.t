#!/usr/bin/env perl

use strict;
use Test::More tests => 2;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $key = "a"x251;

print $sock "set a 1 0 1\r\na\r\n";
is (scalar <$sock>, "STORED\r\n", "Stored key");

print $sock "get a $key\r\n";
is (scalar <$sock>, "CLIENT_ERROR bad command line format\r\n", "illegal key");

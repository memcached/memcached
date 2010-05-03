#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 5;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-X .libs/example_protocol.so');
my $sock = $server->sock;

ok(defined($sock), 'Connection 0');

print $sock "noop\r\n";
is(scalar <$sock>, "OK\r\n", "testing noop");

print $sock "echo foo bar\r\n";
is(scalar <$sock>, "echo [foo] [bar]\r\n", "testing echo");

print $sock "echo 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7\r\n";
is(scalar <$sock>, "echo [1] [2] [3] [4] [5] [6] [7] [8] [9] [0] [1] [2] [3] [4] [5] [6] [7] [8] [9] [0] [1] [2] [3] [4] [5] [6] [7]\r\n", "Max number of args");

print $sock "echo 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8\r\n";
is(scalar <$sock>, "ERROR too many arguments\r\n", "args truncated");

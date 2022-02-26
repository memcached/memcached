#!/usr/bin/env perl

use strict;
use Test::More tests => 2;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

print $sock "verbosity invalid\r\n";
is(scalar <$sock>, "CLIENT_ERROR bad command line format\r\n");

print $sock "slabs automove invalid\r\n";
is(scalar <$sock>, "CLIENT_ERROR bad command line format\r\n");

#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 4;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached();
my $sock = $server->sock;

# set foo (and should get it)
print $sock "set foo 0 2 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

# get metaget
print $sock "metaget foo\r\n";
ok(scalar <$sock> =~ /META foo age:unknown;  exptime:2; from:unknown\r\n/, "metaget retrived successfully");
is(scalar <$sock>, "END\r\n", "end");

# metaget miss
print $sock "metaget foo2\r\n";
is(scalar <$sock>, "END\r\n", "metaget miss");

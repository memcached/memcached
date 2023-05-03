#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 15;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached();
my $sock = $server->sock;

# cache miss
print $sock "gat 10 foo1\r\n";
is(scalar <$sock>, "END\r\n", "cache miss");

# set foo1 and foo2 (and should get it)
print $sock "set foo1 0 2 7\r\nfooval1\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

print $sock "set foo2 0 2 7\r\nfooval2\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo2");

# get and touch it with cas
print $sock "gats 10 foo1 foo2\r\n";
ok(scalar <$sock> =~ /VALUE foo1 0 7 (\d+)\r\n/, "get and touch foo1 with cas regexp success");
is(scalar <$sock>, "fooval1\r\n","value");
ok(scalar <$sock> =~ /VALUE foo2 0 7 (\d+)\r\n/, "get and touch foo2 with cas regexp success");
is(scalar <$sock>, "fooval2\r\n","value");
is(scalar <$sock>, "END\r\n", "end");

# get and touch it without cas
print $sock "gat 10 foo1 foo2\r\n";
ok(scalar <$sock> =~ /VALUE foo1 0 7\r\n/, "get and touch foo1 without cas regexp success");
is(scalar <$sock>, "fooval1\r\n","value");
ok(scalar <$sock> =~ /VALUE foo2 0 7\r\n/, "get and touch foo2 without cas regexp success");
is(scalar <$sock>, "fooval2\r\n","value");
is(scalar <$sock>, "END\r\n", "end");

sleep 2;
mem_get_is($sock, "foo1", "fooval1");
mem_get_is($sock, "foo2", "fooval2");

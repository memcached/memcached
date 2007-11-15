#!/usr/bin/perl

use strict;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached();
my $sock = $server->sock;
my @result;

# gets foo (should not exist)
print $sock "gets foo\r\n";
is(scalar <$sock>, "END\r\n", "gets failed");

# set foo
print $sock "set foo 0 0 6\r\nbarval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored barval");

# gets foo and verify identifier exists
@result = mem_gets($sock, "foo");
mem_gets_is($sock,$result[0],"foo","barval");

# cas fail
print $sock "cas foo 0 0 6 123\r\nbarva2\r\n";
is(scalar <$sock>, "EXISTS\r\n", "cas failed for foo");

# gets foo - success
@result = mem_gets($sock, "foo");
mem_gets_is($sock,$result[0],"foo","barval");

# cas success
print $sock "cas foo 0 0 6 $result[0]\r\nbarva2\r\n";
is(scalar <$sock>, "STORED\r\n", "cas success, set foo");

# delete foo
print $sock "delete foo\r\n";
is(scalar <$sock>, "DELETED\r\n", "deleted foo");

# cas missing
print $sock "cas foo 0 0 6 $result[0]\r\nbarva2\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "cas failed, foo does not exist");


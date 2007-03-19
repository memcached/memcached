#!/usr/bin/perl

use strict;
use Test::More tests => 528;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached();
my $sock = $server->sock;


# set foo (and should get it)
print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "fooval");

# add bar (and should get it)
print $sock "add bar 0 0 6\r\nbarval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored barval");
mem_get_is($sock, "bar", "barval");

# add foo (but shouldn't get new value)
print $sock "add foo 0 0 5\r\nfoov2\r\n";
is(scalar <$sock>, "NOT_STORED\r\n", "not stored");
mem_get_is($sock, "foo", "fooval");

# replace bar (should work)
print $sock "replace bar 0 0 6\r\nbarva2\r\n";
is(scalar <$sock>, "STORED\r\n", "replaced barval 2");

# replace notexist (shouldn't work)
print $sock "replace notexist 0 0 6\r\nbarva2\r\n";
is(scalar <$sock>, "NOT_STORED\r\n", "didn't replace notexist");

# delete foo.
print $sock "delete foo\r\n";
is(scalar <$sock>, "DELETED\r\n", "deleted foo");

# delete foo again.  not found this time.
print $sock "delete foo\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "deleted foo, but not found");

# pipeling is okay
print $sock "set foo 0 0 6\r\nfooval\r\ndelete foo\r\nset foo 0 0 6\r\nfooval\r\ndelete foo\r\n";
is(scalar <$sock>, "STORED\r\n",  "pipeline set");
is(scalar <$sock>, "DELETED\r\n", "pipeline delete");
is(scalar <$sock>, "STORED\r\n",  "pipeline set");
is(scalar <$sock>, "DELETED\r\n", "pipeline delete");


# Test sets up to a large size around 1MB.
# Everything up to 1MB - 1k should succeed, everything 1MB +1k should fail.

my $len = 1024;
while ($len < 1024*1028) {
    my $val = "B"x$len;
    print $sock "set foo_$len 0 0 $len\r\n$val\r\n";
    if ($len > (1024*1024)) {
        is(scalar <$sock>, "SERVER_ERROR object too large for cache\r\n", "failed to store size $len");
    } else {
        is(scalar <$sock>, "STORED\r\n", "stored size $len");
    }
    $len += 2048;
}


#!/usr/bin/perl

use strict;
use Test::More tests => 20;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

# set foo (and should get it)
print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
print $sock "get foo\r\n";
is(scalar <$sock>, "VALUE foo 0 6\r\n", "got FOO value");
is(scalar <$sock>, "fooval\r\n", "got fooval");
is(scalar <$sock>, "END\r\n", "got END");

# add bar (and should get it)
print $sock "add bar 0 0 6\r\nbarval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored barval");
print $sock "get bar\r\n";
is(scalar <$sock>, "VALUE bar 0 6\r\n", "got bar value");
is(scalar <$sock>, "barval\r\n", "got barval");
is(scalar <$sock>, "END\r\n", "got END");

# add foo (but shouldn't get new value)
print $sock "add foo 0 0 5\r\nfoov2\r\n";
is(scalar <$sock>, "NOT_STORED\r\n", "not stored");
print $sock "get foo\r\n";
is(scalar <$sock>, "VALUE foo 0 6\r\n", "got FOO value");
is(scalar <$sock>, "fooval\r\n", "got fooval");
is(scalar <$sock>, "END\r\n", "got END");

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




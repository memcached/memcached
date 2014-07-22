#!/usr/bin/perl

use strict;
use Test::More tests => 25;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $expire;

print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
print $sock "flush_all\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");
mem_get_is($sock, "foo", undef);

# Test flush_all with zero delay.
print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
print $sock "flush_all 0\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");
mem_get_is($sock, "foo", undef);

# check that flush_all doesn't blow away items that immediately get set
print $sock "set foo 0 0 3\r\nnew\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo = 'new'");
mem_get_is($sock, "foo", 'new');

# and the other form, specifying a flush_all time...
my $expire = time() + 2;
print $sock "flush_all $expire\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all in future");

print $sock "set foo 0 0 4\r\n1234\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo = '1234'");
mem_get_is($sock, "foo", '1234');
sleep(3);
mem_get_is($sock, "foo", undef);

print $sock "set foo 0 0 5\r\n12345\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo = '12345'");
mem_get_is($sock, "foo", '12345');
print $sock "flush_all 86400\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all for far future");
# Check foo still exists.
mem_get_is($sock, "foo", '12345');
print $sock "set foo2 0 0 5\r\n54321\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo2 = '54321'");
mem_get_is($sock, "foo", '12345');
mem_get_is($sock, "foo2", '54321');

# Test -F option which disables flush_all
$server = new_memcached('-F');
$sock = $server->sock;

print $sock "set foo 0 0 7\r\nfooval2\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval2");
print $sock "flush_all\r\n";
is(scalar <$sock>, "CLIENT_ERROR flush_all not allowed\r\n", "flush_all was not allowed");
mem_get_is($sock, "foo", "fooval2");


#!/usr/bin/perl

use strict;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $expire;

print $sock "set foo 0 1 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
sleep(1.2);
mem_get_is($sock, "foo", undef);

$expire = time();
print $sock "set foo 0 $expire 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", undef, "already expired");

$expire = time() + 1;
print $sock "set foo 0 $expire 6\r\nfoov+1\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "foov+1");
sleep 1;
mem_get_is($sock, "foo", undef, "now expired");


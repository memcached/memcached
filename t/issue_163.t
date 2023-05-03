#!/usr/bin/env perl

use strict;
use Test::More tests => 7;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $value1 = "A"x66560;
my $value2 = "B"x66570;

print $sock "set key 0 1 66560\r\n$value1\r\n";
is (scalar <$sock>, "STORED\r\n", "stored key");

my $stats  = mem_stats($sock, "slabs");
my $requested = $stats->{"31:mem_requested"};
isnt ($requested, "0", "We should have requested some memory");

sleep(3);
print $sock "set key 0 0 66570\r\n$value2\r\n";
is (scalar <$sock>, "STORED\r\n", "stored key");

my $stats  = mem_stats($sock, "items");
my $reclaimed = $stats->{"items:31:reclaimed"};
is ($reclaimed, "1", "Objects should be reclaimed");

print $sock "delete key\r\n";
is (scalar <$sock>, "DELETED\r\n", "deleted key");

print $sock "set key 0 0 66560\r\n$value1\r\n";
is (scalar <$sock>, "STORED\r\n", "stored key");

my $stats  = mem_stats($sock, "slabs");
my $requested2 = $stats->{"31:mem_requested"};
is ($requested2, $requested, "we've not allocated and freed the same amount");

#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

plan skip_all => 'Fix for Issue 140 was only an illusion';

plan tests => 7;

my $server = new_memcached();
my $sock = $server->sock;

print $sock "set a 0 0 1\r\na\r\n";
is (scalar <$sock>, "STORED\r\n", "stored key");

my $stats  = mem_stats($sock, "items");
my $age = $stats->{"items:1:age"};
isnt ($age, "0", "Age should not be zero");

print $sock "flush_all\r\n";
is (scalar <$sock>, "OK\r\n", "items flushed");

my $stats  = mem_stats($sock, "items");
my $age = $stats->{"items:1:age"};
is ($age, undef, "all should be gone");

print $sock "set a 0 1 1\r\na\r\n";
is (scalar <$sock>, "STORED\r\n", "stored key");

my $stats  = mem_stats($sock, "items");
my $age = $stats->{"items:1:age"};
isnt ($age, "0", "Age should not be zero");

sleep(3);

my $stats  = mem_stats($sock, "items");
my $age = $stats->{"items:1:age"};
is ($age, undef, "all should be gone");

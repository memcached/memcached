#!/usr/bin/env perl

use strict;
use Test::More tests => 11;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached("-o no_modern");
my $sock = $server->sock;
my $value = "B"x10;
my $key = 0;
my $key_count = 10;

for ($key = 0; $key < $key_count; $key++) {
    print $sock "set key$key 0 0 10\r\n$value\r\n";
    is (scalar <$sock>, "STORED\r\n", "stored key$key");
}

my $stats = mem_stats($sock, "slabs");
my $stats2 = mem_stats($sock, "items");
my $req = $stats2->{"items:1:mem_requested"};
my $top = $stats->{"1:chunk_size"} * $key_count;
# unreasonable for the result to be < 500 bytes (min item header is 48), but
# should be less than the maximum potential number.
ok ($req > 500 && $req < $top, "Check allocated size: $req $top");

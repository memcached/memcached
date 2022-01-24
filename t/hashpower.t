#!/usr/bin/perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Config;

my $server = new_memcached();
my $stats = mem_stats($server->sock);
my $pointer_size = $stats->{'pointer_size'};
my $min_hash_power_level = $stats->{'hash_power_level'};
my $max_hash_power_level = 0;
my $pointer_bytes = 0;

if ($pointer_size == 64) {
    $pointer_bytes = 8;
    $max_hash_power_level = 32;
} elsif ($pointer_size == 32) {
    $pointer_bytes = 4;
    $max_hash_power_level = 29;
} else {
    plan skip_all => "Unexpected pointer size: $pointer_size";
}

for my $hash_power_level ($min_hash_power_level..$max_hash_power_level) {
    my $hash_bytes = (1<<$hash_power_level) * $pointer_bytes;
    my $server = new_memcached("-o hashpower=$hash_power_level");
    my $stats = mem_stats($server->sock);
    is($stats->{'hash_power_level'}, $hash_power_level, "hashpower set to $hash_power_level");
    is($stats->{'hash_bytes'}, $hash_bytes, "hash bytes at hashpower $hash_power_level");
}

done_testing();

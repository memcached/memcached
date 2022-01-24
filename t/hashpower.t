#!/usr/bin/perl

use strict;
use Test::More tests => 34;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Config;

for my $hash_power_level (16..32) {
    my $hash_bytes = (1<<$hash_power_level) * $Config{ivsize};
    my $server = new_memcached("-o hashpower=$hash_power_level");
    my $stats = mem_stats($server->sock);
    is($stats->{'hash_power_level'}, $hash_power_level, "hashpower set to $hash_power_level");
    is($stats->{'hash_bytes'}, $hash_bytes, "hash bytes at hashpower $hash_power_level");
}

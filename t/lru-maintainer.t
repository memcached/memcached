#!/usr/bin/perl

use strict;
use Test::More tests => 224;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 6 -o lru_maintainer,lru_crawler');
my $sock = $server->sock;

for (1 .. 10) {
    print $sock "set ifoo$_ 0 1 2\r\nok\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

sleep 3;

{
    my $stats = mem_stats($sock);
    is($stats->{reclaimed}, 10, "expired key automatically reclaimed");
}

my $value = "B"x66560;

print $sock "set canary 0 0 66560\r\n$value\r\n";
is(scalar <$sock>, "STORED\r\n", "stored canary key");

# Now flush the slab class with junk.
for (my $key = 0; $key < 100; $key++) {
    if ($key == 30) {
        my $stats;
        for (0..2) {
            # Give the juggler some time to move. some platforms suffer at
            # this more than others (solaris amd64?)
            $stats = mem_stats($sock, "items");
            if ($stats->{"items:31:moves_to_cold"} == 0) { sleep 1; next; }
            last;
        }
        isnt($stats->{"items:31:moves_to_cold"}, 0, "moved some items to cold");
        # Fetch the canary once, so it's now marked as active.
        mem_get_is($sock, "canary", $value);
    }
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

{
    my $stats = mem_stats($sock);
    isnt($stats->{evictions}, 0, "some evictions happened");
    my $istats = mem_stats($sock, "items");
    isnt($stats->{"items:31:number_warm"}, 0, "our canary moved to warm");
}

# Key should've been saved to the WARM_LRU, and still exists.
mem_get_is($sock, "canary", $value);

# Test NOEXP_LRU
$server = new_memcached('-m 2 -o lru_maintainer,lru_crawler,expirezero_does_not_evict');
$sock = $server->sock;

{
    my $stats = mem_stats($sock, "settings");
    is($stats->{expirezero_does_not_evict}, "yes");
}

print $sock "set canary 0 0 66560\r\n$value\r\n";
is(scalar <$sock>, "STORED\r\n", "stored noexpire canary key");

{
    my $stats = mem_stats($sock, "items");
    is($stats->{"items:31:number_noexp"}, 1, "one item in noexpire LRU");
    is($stats->{"items:31:number_hot"}, 0, "item did not go into hot LRU");
}

# *Not* fetching the key, and flushing the slab class with junk.
# Using keys with actual TTL's here.
for (my $key = 0; $key < 100; $key++) {
    print $sock "set key$key 0 3600 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

{
    my $stats = mem_stats($sock, "items");
    isnt($stats->{evictions}, 0, "some evictions happened");
    isnt($stats->{number_hot}, 0, "nonzero exptime items went into hot LRU");
}
# Canary should still exist, even unfetched, because it's protected by
# noexpire.
mem_get_is($sock, "canary", $value);

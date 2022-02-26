#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 226;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# Regression test for underestimating the size of items after the large memory
# change.
my $server = new_memcached('-m 3 -o lru_maintainer,lru_crawler -l 127.0.0.1');
my $sock = $server->sock;
my $keystub = "X"x200;
for (1 .. 15000) {
    print $sock "set $keystub$_ 0 0 2 noreply\r\nok\r\n";
}
# There's probably already an error on the wire, so we'll see that.
$keystub .= "20001";
print $sock "set $keystub 0 0 2\r\nok\r\n";
is(scalar <$sock>, "STORED\r\n", "stored key without OOM");

# Basic tests
$server = new_memcached('-m 6 -o lru_maintainer,lru_crawler -l 127.0.0.1');
$sock = $server->sock;

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
        # Items need two fetches to become active
        mem_get_is($sock, "canary", $value);
        mem_get_is($sock, "canary", $value);
        $stats = mem_stats($sock);
        # The maintainer thread needs to juggle a bit to actually rescue an
        # item. If it's slow we could evict after resuming setting.
        sleep 1;
        for (0..4) {
            my $s2 = mem_stats($sock);
            if ($s2->{lru_maintainer_juggles} - $stats->{lru_maintainer_juggles} < 5) {
                sleep 1;
                next;
            }
            last;
        }
        $stats = mem_stats($sock, "items");
        isnt($stats->{"items:31:moves_to_warm"}, 0, "our canary moved to warm");
    }
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

{
    my $stats = mem_stats($sock);
    isnt($stats->{evictions}, 0, "some evictions happened");
    use Data::Dumper qw/Dumper/;
}

# Key should've been saved to the WARM_LRU, and still exists.
mem_get_is($sock, "canary", $value);

# Test TEMP_LRU
$server = new_memcached('-m 2 -o lru_maintainer,lru_crawler,temporary_ttl=61');
$sock = $server->sock;

{
    my $stats = mem_stats($sock, "settings");
    is($stats->{temp_lru}, "yes");
}

print $sock "set canary 0 30 66560\r\n$value\r\n";
is(scalar <$sock>, "STORED\r\n", "stored temporary canary key");

{
    my $stats = mem_stats($sock, "items");
    is($stats->{"items:31:number_hot"}, 0, "item did not go into hot LRU");
}

# *Not* fetching the key, and flushing the slab class with junk.
# Using keys with higher TTL's here.
for (my $key = 0; $key < 100; $key++) {
    print $sock "set key$key 0 3600 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

{
    my $stats = mem_stats($sock, "items");
    isnt($stats->{"items:31:evictions"}, 0, "some evictions happened");
    isnt($stats->{"items:31:number_hot"}, 0, "high exptime items went into hot LRU");
    is($stats->{"items:31:number_temp"}, 1, "still one item in temporary LRU");
}
# Canary should still exist, even unfetched, because it's protected by
# temp LRU
mem_get_is($sock, "canary", $value);

#!/usr/bin/perl
# Test the 'stats items' evictions counters.

use strict;
use Test::More tests => 309;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached("-m 3 -o modern,slab_automove_window=3");
my $sock = $server->sock;
my $value = "B"x66560;
my $key = 0;

# These aren't set to expire.
for ($key = 0; $key < 40; $key++) {
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

my $stats  = mem_stats($sock);
my $evicted = $stats->{evictions};
isnt($evicted, "0", "check evicted");

# We're past the memory limit. Try adjusting maxbytes upward.
$stats = mem_stats($sock, "settings");
my $pre_maxbytes = $stats->{"maxbytes"};
print $sock "cache_memlimit 8\r\n";
is(scalar <$sock>, "OK\r\n", "bumped maxbytes from 3m to 8m");

# Confirm maxbytes updated.
$stats = mem_stats($sock, "settings");
isnt($stats->{"maxbytes"}, $pre_maxbytes, "stats settings maxbytes updated");

# Check for total_malloced increasing as new memory is added
$stats = mem_stats($sock, "slabs");
my $t_malloc = $stats->{"total_malloced"};

print $sock "set toast 0 0 66560\r\n$value\r\n";
is(scalar <$sock>, "STORED\r\n", "stored toast");
$stats = mem_stats($sock, "slabs");
cmp_ok($stats->{"total_malloced"}, '>', $t_malloc, "stats slabs total_malloced increased");

$stats = mem_stats($sock);
my $new_evicted = $stats->{evictions};
cmp_ok($new_evicted, '==', $evicted, "no new evictions");

# Bump up to 16, fill a bit more, then delete everything.
print $sock "cache_memlimit 16\r\n";
is(scalar <$sock>, "OK\r\n", "bumped maxbytes from 8m to 16m");
for (;$key < 150; $key++) {
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

# Grab total_malloced after filling everything up.
$stats = mem_stats($sock, "slabs");
$t_malloc = $stats->{"total_malloced"};
print $sock "cache_memlimit 8\r\n";
is(scalar <$sock>, "OK\r\n", "bumped maxbytes from 16m to 8m");

# Remove all of the keys, allowing the slab rebalancer to push pages toward
# the global page pool.
for ($key = 0; $key < 150; $key++) {
    print $sock "delete key$key\r\n";
    like(scalar <$sock>, qr/(DELETED|NOT_FOUND)\r\n/, "deleted key$key");
}

# If memory limit is lower, it should free those pages back to the OS.
my $reduced = 0;
for (my $tries = 0; $tries < 6; $tries++) {
    sleep 1;
    $stats = mem_stats($sock, "slabs");
    $reduced = $stats->{"total_malloced"} if ($t_malloc > $stats->{"total_malloced"});
    last if $reduced;
}

isnt($reduced, 0, "total_malloced reduced to $reduced");

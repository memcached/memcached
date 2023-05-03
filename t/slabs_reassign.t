#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 131;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# Enable manual slab reassign, cap at 6 slabs
my $server = new_memcached('-o slab_reassign -m 4');
my $stats = mem_stats($server->sock, ' settings');
is($stats->{slab_reassign}, "yes");

my $sock = $server->sock;

# Fill a largeish slab until it evicts (honors the -m 6)
my $bigdata = 'x' x 70000; # slab 31
for (1 .. 60) {
    print $sock "set bfoo$_ 0 0 70000\r\n", $bigdata, "\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

# Fill a smaller slab until it evicts
my $smalldata = 'y' x 20000; # slab 25
for (1 .. 60) {
    print $sock "set sfoo$_ 0 0 20000\r\n", $smalldata, "\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

my $items_before = mem_stats($sock, "items");
isnt($items_before->{"items:31:evicted"}, 0, "slab 31 evicted is nonzero");
isnt($items_before->{"items:25:evicted"}, 0, "slab 25 evicted is nonzero");

my $slabs_before = mem_stats($sock, "slabs");

# Invalid argument test
print $sock "slabs reassign invalid1 invalid2\r\n";
is(scalar <$sock>, "CLIENT_ERROR bad command line format\r\n");

# Move a large slab to the smaller slab
print $sock "slabs reassign 31 25\r\n";
is(scalar <$sock>, "OK\r\n", "slab rebalancer started");

# Still working out how/if to signal the thread. For now, just sleep.
sleep 2;

# Check that stats counters increased
my $slabs_after = mem_stats($sock, "slabs");
$stats = mem_stats($sock);

isnt($stats->{slabs_moved}, 0, "slabs moved is nonzero");

# Check that slab stats reflect the change
ok($slabs_before->{"31:total_pages"} != $slabs_after->{"31:total_pages"},
    "slab 31 pagecount changed");
ok($slabs_before->{"25:total_pages"} != $slabs_after->{"25:total_pages"},
    "slab 25 pagecount changed");

# Try to move another slab, see that you can move two in a row
print $sock "slabs reassign 31 25\r\n";
like(scalar <$sock>, qr/^OK/, "Cannot re-run against class with empty space");

# Try to move a page backwards. Should complain that source class isn't "safe"
# to move from.
# TODO: Wait until the above command completes, then try to move it back?
# Seems pointless...
#print $sock "slabs reassign 25 31\r\n";
#like(scalar <$sock>, qr/^UNSAFE/, "Cannot move an unsafe slab back");

# Try to insert items into both slabs
print $sock "set bfoo51 0 0 70000\r\n", $bigdata, "\r\n";
is(scalar <$sock>, "STORED\r\n", "stored key");

print $sock "set sfoo51 0 0 20000\r\n", $smalldata, "\r\n";
is(scalar <$sock>, "STORED\r\n", "stored key");

# Do need to come up with better automated tests for this.

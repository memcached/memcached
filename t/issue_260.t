#!/usr/bin/perl
# Issue #260 is a terrible bug.
# In order to run this test:
# * checkout 1.4.15
# * change TAIL_REPAIR_TIME from (3 * 3600) to 3
# Now it should cause an assert. Patches can be tested to fix it.

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

plan skip_all => "Only possible to test #260 under artificial conditions";
exit 0;
plan tests => 11074;
# assuming max slab is 1M and default mem is 64M
my $server = new_memcached();
my $sock = $server->sock;

# create a big value for the largest slab
my $max = 1024 * 1024;
my $big = 'x' x (1024 * 1024 - 250);

ok(length($big) > 512 * 1024);
ok(length($big) < 1024 * 1024);

# set the big value
my $len = length($big);
print $sock "set big 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored big");
mem_get_is($sock, "big", $big);

# no evictions yet
my $stats = mem_stats($sock);
is($stats->{"evictions"}, "0", "no evictions to start");

# set many big items, enough to get evictions
for (my $i = 0; $i < 100; $i++) {
  print $sock "set item_$i 0 0 $len\r\n$big\r\n";
  is(scalar <$sock>, "STORED\r\n", "stored item_$i");
}

# some evictions should have happened
my $stats = mem_stats($sock);
my $evictions = int($stats->{"evictions"});
ok($evictions == 37, "some evictions happened");

# the first big value should be gone
mem_get_is($sock, "big", undef);

# the earliest items should be gone too
for (my $i = 0; $i < $evictions - 1; $i++) {
  mem_get_is($sock, "item_$i", undef);
}

# check that the non-evicted are the right ones
for (my $i = $evictions - 1; $i < $evictions + 4; $i++) {
  mem_get_is($sock, "item_$i", $big);
}

# Now we fill a slab with incrementable items...
for (my $i = 0; $i < 10923; $i++) {
  print $sock "set sitem_$i 0 0 1\r\n1\r\n";
  is(scalar <$sock>, "STORED\r\n", "stored sitem_$i");
}

my $stats = mem_stats($sock);
my $evictions = int($stats->{"evictions"});
ok($evictions == 38, "one more eviction happened: $evictions");

# That evicted item was the first one we put in.
mem_get_is($sock, "sitem_0", undef);

sleep 15;

# Now we increment the item which should be on the tail.
# THIS asserts the memcached-debug binary.
print $sock "incr sitem_1 1\r\n";
is(scalar <$sock>, "2\r\n", "incremented to two");

#my $stats = mem_stats($sock, "slabs");
#is($stats->{"1:free_chunks"}, 0, "free chunks should still be 0");

#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

# Tests for condition where the slab page mover causes the CAS value to change
# when rescuring memory during a page move.

my $server = new_memcached('-o slab_reassign,no_slab_automove -m 8');

my $sock = $server->sock;

my $keycount = 60;
# Fill a largeish slab until it evicts (honors the -m)
my $bigdata = 'x' x 70000;
for (1 .. $keycount) {
    print $sock "set bfoo$_ 0 0 70000\r\n", $bigdata, "\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

my $stats = mem_stats($sock, "items");
is($stats->{"items:31:number"}, $keycount, "items in the expected slab class");

my ($cas, $val) = mem_gets($sock, "bfoo5");
isnt($cas, 0, "got a real CAS back for one of the keys");

# Make enough space in the source slab class so moving doesn't eject items
for (6 .. $keycount) {
    print $sock "delete bfoo$_\r\n";
    is(scalar <$sock>, "DELETED\r\n");
}

# force re-assign the first page to trigger the bug.
print $sock "slabs reassign 31 5\r\n";
is(scalar <$sock>, "OK\r\n", "slab rebalancer started");

# let the rebalancer work
sleep 2;

my ($cas_after, $val_after) = mem_gets($sock, "bfoo5");
is($cas, $cas_after, "CAS value match after page move");

done_testing();

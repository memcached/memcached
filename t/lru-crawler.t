#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 70257;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 32 -o no_modern');
{
    my $stats = mem_stats($server->sock, ' settings');
    is($stats->{lru_crawler}, "no");
}

my $sock = $server->sock;

# Fill a slab a bit.
# Some immortal items, some long expiring items, some short expiring items.
# Done so the immortals end up at the tail.
for (1 .. 30) {
    print $sock "set ifoo$_ 0 0 2\r\nok\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}
for (1 .. 30) {
    print $sock "set lfoo$_ 0 3600 2\r\nok\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}
for (1 .. 30) {
    print $sock "set sfoo$_ 0 1 2\r\nok\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

{
    my $slabs = mem_stats($sock, "slabs");
    is($slabs->{"1:used_chunks"}, 90, "slab1 has 90 used chunks");
}

sleep 3;

print $sock "lru_crawler enable\r\n";
is(scalar <$sock>, "OK\r\n", "enabled lru crawler");
{
    my $stats = mem_stats($server->sock, ' settings');
    is($stats->{lru_crawler}, "yes");
}

print $sock "lru_crawler crawl 1\r\n";
is(scalar <$sock>, "OK\r\n", "kicked lru crawler");
while (1) {
    my $stats = mem_stats($sock);
    last unless $stats->{lru_crawler_running};
    sleep 1;
}

{
    my $slabs = mem_stats($sock, "slabs");
    is($slabs->{"1:used_chunks"}, 60, "slab1 now has 60 used chunks");
    my $items = mem_stats($sock, "items");
    is($items->{"items:1:crawler_reclaimed"}, 30, "slab1 has 30 reclaims");
}

# Ensure pipelined commands fail with metadump.
# using metaget because get forces pipeline flush.
{
    print $sock "mg foo v\r\nlru_crawler metadump all\r\n";
    is(scalar <$sock>, "EN\r\n");
    is(scalar <$sock>, "ERROR cannot pipeline other commands before metadump\r\n");
}

# Check that crawler metadump works correctly.
{
    print $sock "lru_crawler metadump all\r\n";
    my $count = 0;
    while (<$sock>) {
        last if /^(\.|END)/;
        /^(key=) (\S+).*([^\r\n]+)/;
        $count++;
    }
    is ($count, 60, "metadump all returns all items");
}

for (1 .. 30) {
    mem_get_is($sock, "ifoo$_", "ok");
    mem_get_is($sock, "lfoo$_", "ok");
    mem_get_is($sock, "sfoo$_", undef);
}

# add a few more items into a different slab class
my $mfdata = 'x' x 512;
for (1 .. 30) {
    print $sock "set mfoo$_ 0 0 512\r\n$mfdata\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

# set enough small values to ensure bucket chaining happens
# ... but not enough that hash table expansion happens.
# TODO: check hash power level?
my %bfoo = ();
for (1 .. 70000) {
    print $sock "set bfoo$_ 0 0 1 noreply\r\nz\r\n";
    $bfoo{$_} = 1;
}
{
    print $sock "version\r\n";
    my $res = <$sock>;
    like($res, qr/^VERSION/, "bulk sets completed");
}

# Check metadump hash table walk returns correct number of items.
{
    print $sock "lru_crawler metadump hash\r\n";
    my $count = 0;
    while (<$sock>) {
        last if /^(\.|END)/;
        if (/^key=bfoo(\S+)/) {
            ok(exists $bfoo{$1}, "found bfoo key $1 is still in test hash");
            delete $bfoo{$1};
        }
        $count++;
    }
    is ($count, 70090, "metadump hash returns all items");
    is ((keys %bfoo), 0, "metadump found all bfoo keys");
}

print $sock "lru_crawler disable\r\n";
is(scalar <$sock>, "OK\r\n", "disabled lru crawler");
my $settings_match = 0;
# TODO: we retry a few times since the settings value is changed
# outside of a memory barrier, but the thread is stopped before the OK is
# returned.
# At some point better handling of the setings synchronization should happen.
for (1 .. 10) {
    my $stats = mem_stats($server->sock, ' settings');
    if ($stats->{lru_crawler} eq "no") {
        $settings_match = 1;
        last;
    }
    sleep 1;
}
is($settings_match, 1, "settings output matches crawler state");

$server->stop;

# Test initializing crawler from starttime.
$server = new_memcached('-m 32 -o no_modern,lru_crawler');
$sock = $server->sock;

for (1 .. 30) {
    print $sock "set sfoo$_ 0 1 2\r\nok\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

sleep 3;

print $sock "lru_crawler crawl 1\r\n";
is(scalar <$sock>, "OK\r\n", "kicked lru crawler");
while (1) {
    my $stats = mem_stats($sock);
    last unless $stats->{lru_crawler_running};
    sleep 1;
}

{
    my $slabs = mem_stats($sock, "slabs");
    is($slabs->{"1:used_chunks"}, 0, "slab1 now has 0 used chunks");
}

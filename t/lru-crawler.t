#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 224;
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
    is ($count, 60);
}

for (1 .. 30) {
    mem_get_is($sock, "ifoo$_", "ok");
    mem_get_is($sock, "lfoo$_", "ok");
    mem_get_is($sock, "sfoo$_", undef);
}

print $sock "lru_crawler disable\r\n";
is(scalar <$sock>, "OK\r\n", "disabled lru crawler");
{
    my $stats = mem_stats($server->sock, ' settings');
    is($stats->{lru_crawler}, "no");
}

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

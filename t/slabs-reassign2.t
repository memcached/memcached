#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 12;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

my $server = new_memcached('-m 60 -o slab_reassign,slab_automove,lru_crawler,lru_maintainer,slab_automove_window=3');
my $sock = $server->sock;

my $value = "B"x11000;
my $keycount = 5000;

my $res;
for (1 .. $keycount) {
    print $sock "set nfoo$_ 0 0 11000 noreply\r\n$value\r\n";
}

my $todelete = 0;
{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{curr_items}, '>', 4000, "stored at least 4000 11k items");
    $todelete = $stats->{curr_items};
#    for ('evictions', 'reclaimed', 'curr_items', 'cmd_set', 'bytes') {
#        print STDERR "$_: ", $stats->{$_}, "\n";
#    }
}

# Make room in old class so rescues can happen when we switch slab classes.
for (1 .. $todelete) {
    next unless $_ % 2 == 0;
    print $sock "delete nfoo$_ noreply\r\n";
}

{
    my $tries;
    for ($tries = 20; $tries > 0; $tries--) {
        sleep 1;
        my $stats = mem_stats($sock);
        if ($stats->{slab_global_page_pool} > 24) {
            last;
        }
    }
    cmp_ok($tries, '>', 0, 'some pages moved back to global pool');
}

$value = "B"x7000;
for (1 .. $keycount) {
    print $sock "set ifoo$_ 0 0 7000 noreply\r\n$value\r\n";
}

my $missing = 0;
my $hits = 0;
for (1 .. $keycount) {
    print $sock "get ifoo$_\r\n";
    my $body = scalar(<$sock>);
    my $expected = "VALUE ifoo$_ 0 7000\r\n$value\r\nEND\r\n";
    if ($body =~ /^END/) {
        $missing++;
    } else {
        $body .= scalar(<$sock>) . scalar(<$sock>);
        if ($body ne $expected) {
            print STDERR "Something terrible has happened: $expected\nBODY:\n$body\nDONETEST\n";
        } else {
            $hits++;
        }
    }
}
#print STDERR "HITS: $hits, MISSES: $missing\n";

{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{evictions}, '<', 2000, 'evictions were less than 2000');
#    for ('evictions', 'reclaimed', 'curr_items', 'cmd_set', 'bytes') {
#        print STDERR "$_: ", $stats->{$_}, "\n";
#    }
}

# Force reassign evictions by moving too much memory manually.
{
    my $s = mem_stats($sock, 'slabs');
    my $max_pages = 0;
    my $scls = 0;
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+)\:total_pages/;
        if ($s->{$k} > $max_pages) {
            $max_pages = $s->{$k};
            $scls = $1;
        }
    }
    my $tries;
    for ($tries = 10; $tries > 0; $tries--) {
        print $sock "slabs reassign $scls 1\r\n";
        my $res = <$sock>;
        sleep 1;
        my $s = mem_stats($sock);
        last if $s->{slab_reassign_evictions_nomem} > 0;
    }
    cmp_ok($tries, '>', 0, 'some reassign evictions happened');
}
cmp_ok($hits, '>', 2000, 'were able to fetch back some of the small keys');
my $stats_done = mem_stats($sock);
cmp_ok($stats_done->{slab_reassign_rescues}, '>', 0, 'some reassign rescues happened');

print $sock "flush_all\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");
my $tries;
for ($tries = 20; $tries > 0; $tries--) {
    sleep 1;
    my $stats = mem_stats($sock);
    if ($stats->{slab_global_page_pool} > 50) {
        last;
    }
}
cmp_ok($tries, '>', 0, 'reclaimed at least 50 pages before timeout');

{
    my $stats = mem_stats($sock, "slabs");
    is($stats->{total_malloced}, 62914560, "total_malloced is what we expect");
}

# Set into an entirely new class. Overload a bit to try to cause problems.
$value = "B"x4096;
for (1 .. $keycount * 4) {
    print $sock "set jfoo$_ 0 0 4096 noreply\r\n$value\r\n";
}

{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{curr_items}, '>', 10000, "stored at least 10000 4k items");
    is($stats->{slab_global_page_pool}, 0, "drained the global page pool");
}

{
    my $stats = mem_stats($sock, "slabs");
    is($stats->{total_malloced}, 62914560, "total_malloced is same after re-assignment");
}

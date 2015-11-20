#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 11;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 60 -o slab_reassign,slab_automove=2,lru_crawler,lru_maintainer');
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
    $todelete = $stats->{curr_items} / 2;
#    for ('evictions', 'reclaimed', 'curr_items', 'cmd_set', 'bytes') {
#        print STDERR "$_: ", $stats->{$_}, "\n";
#    }
}

# Make room in old class so rescues can happen when we switch slab classes.
for (1 .. $todelete) {
    print $sock "delete nfoo$_ noreply\r\n";
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

cmp_ok($hits, '>', 4000, 'were able to fetch back 2/3rds of 8k keys');
my $stats_done = mem_stats($sock);
cmp_ok($stats_done->{slab_reassign_rescues}, '>', 0, 'some reassign rescues happened');
cmp_ok($stats_done->{slab_reassign_evictions_nomem}, '>', 0, 'some reassign evictions happened');

print $sock "flush_all\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");
my $tries;
for ($tries = 20; $tries > 0; $tries--) {
    sleep 1;
    my $stats = mem_stats($sock);
    if ($stats->{slab_global_page_pool} == 56) {
        last;
    }
}
cmp_ok($tries, '>', 0, 'reclaimed 61 pages before timeout');

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

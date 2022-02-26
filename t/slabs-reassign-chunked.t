#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 60 -o slab_reassign,slab_automove,lru_crawler,lru_maintainer,slab_chunk_max=4096');
my $sock = $server->sock;

sub dump_stats {
    my $s = shift;
    my $filter = shift || '';
    for my $k (sort keys %$s) {
        if ($filter) {
            next unless $k =~ m/$filter/;
        }
        print STDERR "STAT: $k = ", $s->{$k}, "\n";
    }
}

my $value;
{
    my @chars = ("C".."Z");
    for (1 .. 11000) {
        $value .= $chars[rand @chars];
    }
}
my $keycount = 5100;

my $res;
for (1 .. $keycount) {
#    print STDERR "HI $_\n";
    print $sock "set nfoo$_ 0 0 11000 noreply\r\n$value\r\n";
#    print $sock "set nfoo$_ 0 0 11000\r\n$value\r\n";
#    my $res = scalar <$sock>;
#    print STDERR "RES: $res\n";
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

{
    my $s = mem_stats($sock, 'slabs');
    my $sid;
    # Find the highest ID to source from.
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+):/;
        $sid = $s->{$k} if $s->{$k} > $1;
    }
    for (my $x = 0; $x < 3; $x++) {
        print $sock "slabs reassign 17 0\r\n";
        my $res = scalar <$sock>;
        chomp $res;
    #    print STDERR "SLABS REASSIGN RESULT: $res\n";
        sleep 1;
    }
}

# Make room in old class so rescues can happen when we switch slab classes.
#for (1 .. $todelete) {
#    print $sock "delete nfoo$_ noreply\r\n";
#}

# Give  LRU mover some time to reclaim slab chunks.
#sleep 1;

{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{slab_global_page_pool}, '>', 0, 'global page pool > 0');
    cmp_ok($stats->{slab_reassign_chunk_rescues}, '>', 0, 'some chunk rescues happened');
}

{
    my $hits = 0;
    for (1 .. $keycount) {
        print $sock "get nfoo$_\r\n";
        my $body = scalar(<$sock>);
        my $expected = "VALUE nfoo$_ 0 11000\r\n$value\r\nEND\r\n";
        if ($body =~ /^END/) {
            next;
        } else {
            $body .= scalar(<$sock>) . scalar(<$sock>);
            if ($body ne $expected) {
                die "Something terrible has happened: $expected\nBODY:\n$body\nDONETEST\n";
            }
            $hits++;
        }
    }
    cmp_ok($hits, '>', 0, "fetched back $hits values after reassignment");
}

$value = "A"x3000;
for (1 .. $keycount) {
    print $sock "set ifoo$_ 0 0 3000 noreply\r\n$value\r\n";
}

my $missing = 0;
my $hits = 0;
for (1 .. $keycount) {
    print $sock "get ifoo$_\r\n";
    my $body = scalar(<$sock>);
    my $expected = "VALUE ifoo$_ 0 3000\r\n$value\r\nEND\r\n";
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
cmp_ok($stats_done->{slab_reassign_chunk_rescues}, '>', 0, 'some reassign chunk rescues happened');
# Reassign rescues won't happen here because the headers are of a different
# size and we aren't moving pages out of that slab class
#cmp_ok($stats_done->{slab_reassign_rescues}, '>', 0, 'some reassign rescues happened');
cmp_ok($stats_done->{slab_reassign_evictions_nomem}, '>', 0, 'some reassign evictions happened');


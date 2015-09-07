#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 3;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 64 -o slab_reassign,slab_automove=2,lru_crawler,lru_maintainer');
my $sock = $server->sock;

my $value = "B"x10240;
my $keycount = 6000;

my $res;
for (1 .. $keycount) {
    print $sock "set nfoo$_ 0 0 10240 noreply\r\n$value\r\n";
}

{
    my $stats = mem_stats($sock);
    is($stats->{curr_items}, $keycount, "stored $keycount 10k items");
#    for ('evictions', 'reclaimed', 'curr_items', 'cmd_set', 'bytes') {
#        print STDERR "$_: ", $stats->{$_}, "\n";
#    }
}

$value = "B"x8096;
for (1 .. $keycount) {
    print $sock "set ifoo$_ 0 0 8096 noreply\r\n$value\r\n";
}

my $missing = 0;
my $hits = 0;
for (1 .. $keycount) {
    print $sock "get ifoo$_\r\n";
    my $body = scalar(<$sock>);
    my $expected = "VALUE ifoo$_ 0 8096\r\n$value\r\nEND\r\n";
    if ($body =~ /^END/) {
        $missing++;
    } else {
        $body .= scalar(<$sock>) . scalar(<$sock>);
        if ($body ne $expected) {
            print STDERR "Something terrible has happened: $body\n";
        } else {
            $hits++;
        }
    }
}
#print STDERR "HITS: $hits, MISSES: $missing\n";

{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{evictions}, '<', 1000, 'evictions were less than 1000');
#    for ('evictions', 'reclaimed', 'curr_items', 'cmd_set', 'bytes') {
#        print STDERR "$_: ", $stats->{$_}, "\n";
#    }
}

cmp_ok($hits, '>', 4000, 'were able to fetch back 2/3rds of 8k keys');

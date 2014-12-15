#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 111;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 32 -I 100k -o slab_reassign,lru_crawler,slab_automove=3,release_mem_sleep=1,release_mem_start=40,release_mem_stop=10,lru_crawler_interval=5');
{
    my $stats = mem_stats($server->sock, ' settings');
    is($stats->{slab_automove}, "3");
    is($stats->{release_mem_sleep}, "1");
    is($stats->{release_mem_start}, "40");
    is($stats->{release_mem_stop}, "10");
    is($stats->{lru_crawler_interval}, "5");
}

my $sock = $server->sock;
# Fill a slab .
my $data = 'y' x 20000; # slab 25

for (1 .. 100) {
    print $sock "set ifoo$_ 0 30 20000\r\n$data\r\n";
    is(scalar <$sock>, "STORED\r\n");
}

my $stats = mem_stats($sock);
my $pid = $stats->{pid};
#print $pid;
my $mem_before_release=`ps -p $pid -orss= `;
print "Memory before release is(kB):".$mem_before_release;


{
    my $slabs = mem_stats($sock, "slabs");
    is($slabs->{"25:total_pages"}, 25, "slab 25 has 25 used pages");
}

#wait for expire and release memory.
print "wait for expire and release memory... \n";
sleep 32+26;

# check the memory is released.
my $mem_after_release=`ps -p $pid -orss= `;
print "Memory after release is(kB):".$mem_after_release;
is(($mem_before_release-$mem_after_release)>=2048, 1==1, " release memory to system ok.");

{
    my $slabs = mem_stats($sock, "slabs");
    is($slabs->{"25:total_pages"}, 1, "slab 25 now has 1 used pages");
    my $items = mem_stats($sock);
    is($items->{"slabs_freed"}, 24, "slab 25 has 24 freed pages");
}


#<STDIN>;

print $sock "slabs automove 0\r\n";
is(scalar <$sock>, "OK\r\n", "disabled auto move");
{
    my $stats = mem_stats($server->sock, ' settings');
    is($stats->{slab_automove}, "0","disabled auto move ok");
}


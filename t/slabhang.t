#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

plan skip_all => 'Test is flaky. Needs special hooks.';

plan tests => 74;

# start up a server with 10 maximum connections
my $server = new_memcached("-m 16 -o modern");
my $sock = $server->sock;
my $hangsock = $server->new_sock;
my $value = "B"x260144;
my $key = 0;

# disable the normal automover.
print $sock "slabs automove 0\r\n";
is(scalar <$sock>, "OK\r\n", "automover disabled");

# These aren't set to expire.
my $mget = '';
for ($key = 0; $key < 70; $key++) {
    $mget .= "key$key ";
    print $sock "set key$key 0 0 260144\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}
chop $mget;

# Don't intend to read the results, need to fill the socket.
print $hangsock "get $mget\r\n";
#sleep 8;
my $stats = mem_stats($sock, "slabs");
my $source = 0;
for my $key (keys %$stats) {
    if ($key =~ m/^(\d+):total_pages/) {
        my $sid = $1;
        if ($stats->{$key} > 10) {
            $source = $sid;
            last;
        }
    }
}
isnt($source, 0, "found the source slab: $source");

my $busy;
my $tomove = 4;
my $reassign = "slabs reassign $source 1\r\n";
while ($tomove) {
    $busy = 0;
    print $sock $reassign;
    my $res = scalar <$sock>;
    while ($res =~ m/^BUSY/) {
        if ($hangsock && $busy > 5) {
            # unjam the pipeline
            $hangsock->close;
        }
        last if ($busy > 10);
        sleep 1;
        $busy++;
        print $sock $reassign;
        $res = scalar <$sock>;
    }
    last if ($busy > 10);
    $tomove--;
}

ok($busy <= 10, "didn't time out moving pages");

$stats = mem_stats($sock);
isnt($stats->{"slab_reassign_busy_deletes"}, "0", "deleted some busy items");

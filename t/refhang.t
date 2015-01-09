#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 127;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# start up a server with 10 maximum connections
my $server = new_memcached("-m 6");
my $sock = $server->sock;
my $hangsock = $server->new_sock;
my $hangsock2 = $server->new_sock;
my $value = "B"x66560;
my $key = 0;

# These aren't set to expire.
my $mget = '';
for ($key = 0; $key < 120; $key++) {
    $mget .= "key$key " if $key < 115;
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}
chop $mget;

my $stats  = mem_stats($sock, "items");
isnt($stats->{"items:31:evicted"}, "0", "check evicted");

my $lrutail_reflocked = $stats->{"items:31:lrutail_reflocked"};
is($lrutail_reflocked, "0", "check no slab lrutail_reflocked");

$stats = mem_stats($sock);
is($stats->{"lrutail_reflocked"}, "0", "check no total lrutail_reflocked");

# Don't intend to read the results, need to fill the socket.
# TODO: This test would be smarter if we cranked down the socket buffers
# first? Or perhaps used a unix domain socket.
print $hangsock "get $mget\r\n";
#sleep 8;
# Now we try a bunch of sets again, and see if they start coming back as OOM's
for ($key = 121; $key < 240; $key++) {
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    my $res = scalar <$sock>;
}

$stats = mem_stats($sock, "items");
# Some items will OOM since we only clear a handful per alloc attempt.
ok($stats->{"items:31:outofmemory"} > 0, "some ooms happened");
ok($stats->{"items:31:outofmemory"} < 20, "fewer than 20 ooms");
isnt($stats->{"items:31:lrutail_reflocked"}, "0", "nonzero lrutail_reflocked");

$stats = mem_stats($sock);
isnt($stats->{"lrutail_reflocked"}, "0", "nonzero total lrutail_reflocked");

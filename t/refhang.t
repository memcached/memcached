#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 266;

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
my $mget_all = '';
for ($key = 0; $key < 120; $key++) {
    $mget .= "key$key " if $key < 115;
    $mget_all .= "key$key ";
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
    $mget_all .= "key$key ";
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

$stats = mem_stats($sock, "items");
is($stats->{"items:31:outofmemory"}, "0", "check no oom");
isnt($stats->{"items:31:lrutail_reflocked"}, "0", "count lrutail_reflocked");

$stats = mem_stats($sock);
isnt($stats->{"lrutail_reflocked"}, "0", "count total lrutail_reflocked");

# Clear out all that 'hung' traffic
while(<$hangsock> !~ /END/) { };

# Make sure we get a oom when the entire world is refcounted
print $hangsock "get $mget_all\r\n";

# Get all our keys in a different order to make sure some of the cache isn't
# free just because it made it to the tcp buffer
my $revkeys = join(" ", reverse(split(" ", $mget_all)));
print $hangsock2 "get $revkeys\r\n";

for ($key = 240; $key < 260; $key++) {
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "SERVER_ERROR out of memory storing object\r\n", "oom fully lrutail_reflocked");
}

$stats = mem_stats($sock, "items");
isnt($stats->{"items:31:outofmemory"}, "0", "count lrutail_reflocked oom");

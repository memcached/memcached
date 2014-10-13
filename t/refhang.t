#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 240;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# start up a server with 10 maximum connections
my $server = new_memcached("-m 6");
my $sock = $server->sock;
my $hangsock = $server->new_sock;;
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
my $evicted = $stats->{"items:31:evicted"};
isnt($evicted, "0", "check evicted");

# Don't intend to read the results, need to fill the socket.
# TODO: This test would be smarter if we cranked down the socket buffers
# first? Or perhaps used a unix domain socket.
print $hangsock "get $mget\r\n";
#sleep 8;
# Now we try a bunch of sets again, and see if they start coming back as OOM's
for ($key = 121; $key < 240; $key++) {
    print $sock "set key$key 0 0 66560\r\n$value\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key$key");
}

#!/usr/bin/env perl

use strict;
use warnings;

use Test::More tests => 11;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# start up a server with 10 maximum connections
my $server = new_memcached("-o idle_timeout=3 -l 127.0.0.1");
my $sock = $server->sock;

# Make sure we can talk to start with
my $stats = mem_stats($sock);
is($stats->{idle_kicks}, "0", "check stats initial");
isnt($sock->connected(), undef, "check connected");

# Make sure we don't timeout when active
for (my $i = 0; $i < 6; $i++) {
    $stats = mem_stats($sock);
    isnt($stats->{version}, undef, "check active $i");
}
$stats = mem_stats($sock);
is($stats->{idle_kicks}, "0", "check stats 2");

# Make sure we do timeout when not
sleep(10);
mem_stats($sock);   # Network activity, so socket code will see dead socket
sleep(1);
# we run SSL tests over TCP; hence IO::Socket::SSL
# with IO::Socket::IP returns '' or IO::Socket::INET returns undef
# upon disconnecting with the server.
ok(length($sock->connected()) == 0, "check disconnected");

$sock = $server->sock;
$stats = mem_stats($sock);
isnt($stats->{idle_kicks}, 0, "check stats timeout");

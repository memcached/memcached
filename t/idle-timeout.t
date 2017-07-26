#!/usr/bin/perl

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
sleep(5);
mem_stats($sock);   # Network activity, so socket code will see dead socket
sleep(1);
is($sock->connected(), undef, "check disconnected");

$sock = $server->sock;
$stats = mem_stats($sock);
isnt($stats->{idle_kicks}, 0, "check stats timeout");

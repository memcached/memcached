#!/usr/bin/perl
# NOTE: This test never worked. Memcached would ignore maxconns requests lower
# than the current ulimit. Test needs to be updated.

use strict;
use warnings;

use Test::More;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

plan skip_all => "maxconns test does not work";
exit 0;

plan tests => 6;

# start up a server with 10 maximum connections
my $server = new_memcached('-c 100');
my $sock = $server->sock;
my @sockets;

ok(defined($sock), 'Connection 0');
push (@sockets, $sock);


foreach my $conn (1..10) {
  $sock = $server->new_sock;
  ok(defined($sock), "Made connection $conn");
  push(@sockets, $sock);
}

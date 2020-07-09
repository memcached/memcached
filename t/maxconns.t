#!/usr/bin/perl
# NOTE: This test never worked. Memcached would ignore maxconns requests lower
# than the current ulimit. Test needs to be updated.

use strict;
use warnings;

use Test::More;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-c 32');

my $stat_sock = $server->sock;
my @sockets = ();
my $num_sockets;
my $rejected_conns = 0;
for (1 .. 3) {
  my $sock = $server->new_sock;
  if (defined($sock)) {
    push (@sockets, $sock);
  } else {
    $rejected_conns = $rejected_conns + 1;
  }
}
$num_sockets = @sockets;
ok(($num_sockets == 3), 'Got correct num of sockets');

my $stats = mem_stats($stat_sock);
is($stats->{curr_connections}, 4, 'Got correct number of connections');
#once rejected_connections metric is updated correctly, we can check for the failed connections.
$server->stop();
done_testing();

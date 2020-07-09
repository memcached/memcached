#!/usr/bin/perl
# NOTE: This test never worked. Memcached would ignore maxconns requests lower
# than the current ulimit. Test needs to be updated.

use strict;
use warnings;

use Test::More;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-c 30','','true');

my $stat_sock = $server->sock;
my @sockets = ();
my $num_sockets;
my $rejected_conns = 0;
for (1 .. 5) {
  my $sock = $server->new_sock;
  if (defined($sock)) {
    push (@sockets, $sock);
  } else {
    $rejected_conns = $rejected_conns + 1;
  }
}
$num_sockets = @sockets;
ok(($num_sockets == 5), 'Got correct num of sockets');

my $stats = mem_stats($stat_sock);
is($stats->{curr_connections}, 2, 'Got correct number of connections');
is($stats->{rejected_connections}, 4, 'Got correct number of rejected connections');
$server->stop();
done_testing();

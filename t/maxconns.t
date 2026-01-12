#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $max_conn = 1024 ;
# Raise open files limit (RLIMIT_NOFILE) for better compatibility
#
# macOS has a very low default soft limit (256) on open file descriptors,
# causing EMFILE errors after ~270 connections. Increase it programmatically
# (or via system config) to support higher concurrency, matching Linux defaults.
my $soft_limit = `ulimit -n`;
if ($soft_limit && $soft_limit < $max_conn) {
    $max_conn = $soft_limit - 1;
}

my $port = free_port();
my $server = new_memcached("-o maxconns_fast -c $max_conn", $port, -disable_ssl => 1);

test_maxconns($server);

my $ext_path;
if (supports_extstore()) {
    $ext_path = "/tmp/extstore.$$";

    my $port = free_port();
    my $server = new_memcached("-m 64 -U 0 -o maxconns_fast,ext_path=$ext_path:64m -c $max_conn", $port, -disable_ssl => 1);
    test_maxconns($server);
}

sub test_maxconns {
    my $server = shift;

    my $stat_sock = $server->sock;
    my @sockets = ();
    my $num_sockets;
    my $rejected_conns = 0;
    my $stats;
    for (1 .. $max_conn) {
      my $sock = $server->new_sock;
      if (defined($sock)) {
        push(@sockets, $sock);
        $stats = mem_stats($stat_sock);
        if ($stats->{rejected_connections} > $rejected_conns) {
          $rejected_conns = $stats->{rejected_connections};
          my $buffer = "";
          my $length = 31;
          my $res = recv($sock, $buffer, $length, 0);
          if (not $buffer eq '') {
              is($buffer, "ERROR Too many open connections", "Got expected response from the server");
          }
        }
      }
    }

    my $failed = 1;
    for (1 .. 5) {
        $stats = mem_stats($stat_sock);
        if ($stats->{rejected_connections} != 0) {
            $failed = 0;
            last;
        }
        sleep 1;
    }
    is($failed, 0, "rejected connections were observed.");

    for my $s (@sockets) {
        $s->close();
    }

    $server->stop;
    $stat_sock->close();
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

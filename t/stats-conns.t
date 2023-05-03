#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

## First make sure we report UNIX-domain sockets correctly
if (supports_unix_socket()) {
    plan tests => 12;

    my $filename = "/tmp/memcachetest$$";

    my $server = new_memcached("-s $filename");
    my $sock = $server->sock;
    my $stats_sock = $server->new_sock;

    ok(-S $filename, "creating unix domain socket $filename");

    print $sock "set foo 0 0 6\r\n";
    sleep(1);    # so we can test secs_since_last_cmd is nonzero
    print $stats_sock "stats conns\r\n";

    my $stats;
    while (<$stats_sock>) {
        last if /^(\.|END)/;
        $stats .= $_;
    }

    like($stats, qr/STAT \d+:addr /);
    $stats =~ m/STAT (\d+):addr unix:(.*[^\r\n])/g;
    my $listen_fd = $1;
    my $socket_path = $2;
    # getsockname(2) doesn't return socket path on GNU/Hurd (and maybe others)
    SKIP: {
        skip "socket path checking on GNU kernel", 1 if ($^O eq 'gnu');
        is($socket_path, $filename, "unix domain socket path reported correctly");
    };
    $stats =~ m/STAT (\d+):state conn_listening\r\n/g;
    is($1, $listen_fd, "listen socket fd reported correctly");

    like($stats, qr/STAT \d+:state conn_nread/,
         "one client is sending data");
    like($stats, qr/STAT \d+:state conn_parse_cmd/,
         "one client is in command processing");
    like($stats, qr/STAT \d+:secs_since_last_cmd [1-9]\r/,
         "nonzero secs_since_last_cmd");
    like($stats, qr/STAT \d+:listen_addr unix:\/tmp\/memcachetest\d+\r/,
         "found listen_addr for the UNIX-domain socket");

    $server->stop;
    unlink($filename);
} else {
    plan tests => 4;
}

## Now look at TCP

my $server = new_memcached("-l 0.0.0.0");
my $sock = $server->sock;
my $stats_sock = $server->new_sock;

print $sock "set foo 0 0 6\r\n";
print $stats_sock "stats conns\r\n";

my $stats = '';
while (<$stats_sock>) {
    last if /^(\.|END)/;
    $stats .= $_;
}

like($stats, qr/STAT \d+:state conn_listen/, "there is a listen socket");
$stats =~ m/STAT \d+:addr udp:0.0.0.0:(\d+)/;
is($1, $server->udpport, "udp port number is correct");
$stats =~ m/STAT \d+:addr tcp:0.0.0.0:(\d+)/;
print STDERR "PORT: ", $server->port, "\n";
is($1, $server->port, "tcp port number is correct");

$stats =~ m/STAT \d+:listen_addr tcp:0.0.0.0:(\d+)/;
is($1, $server->port, "listen_addr is correct for the tcp port");

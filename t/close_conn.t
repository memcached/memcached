#!/usr/bin/perl
# Tests for the "close_conn" command. Only closes client connections, except the current
# connection.
use strict;
use warnings;

use Test::More tests => 10;

use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached("-l 0.0.0.0");
my $sock = $server->sock;

print $sock "stats conns\r\n";

my $tcp_conn;
my $udp_conn;
my $my_conn;

while (<$sock>) {
    last if /^(\.|END)/;
    $tcp_conn = $_ if not $tcp_conn and m/STAT \d+:addr tcp:0.0.0.0:\d+/;
    $udp_conn = $_ if not $udp_conn and m/STAT \d+:addr udp:0.0.0.0:\d+/;
    $my_conn = $_;
}

$tcp_conn = get_conn_id($tcp_conn);
$udp_conn = get_conn_id($udp_conn);
$my_conn = get_conn_id($my_conn);

my $res;

print $sock "close_conn invalid\r\n";
$res = <$sock>;
is($res,"ERROR Invalid connection id\r\n", "Invalid connection Id");

print $sock "close_conn 1000000000000000000\r\n";
$res = <$sock>;
is($res,"ERROR Invalid connection id\r\n", "Incorrect connection Id");

print $sock "close_conn -1000000000000000000\r\n";
$res = <$sock>;
is($res,"ERROR Invalid connection id\r\n", "Incorrect connection Id");

print $sock "close_conn 1000\r\n";
$res = <$sock>;
is($res,"ERROR Connection not found\r\n", "There's no such connection");

print $sock "close_conn $tcp_conn\r\n";
$res = <$sock>;
is($res,"ERROR Listening connection\r\n", "Cannot close a listening port");

print $sock "close_conn $udp_conn\r\n";
$res = <$sock>;
is($res,"ERROR UDP connection\r\n", "Cannot close a UDP port");

print $sock "close_conn $my_conn\r\n";
$res = <$sock>;
is($res, "ERROR Current connection\r\n", "Cannot close myself");

my $new_sock = $server->new_sock;
print $new_sock "get foo\r\n";
$res = <$new_sock>;
is($res, "END\r\n", "New connection is active");

print $sock "stats conns\r\n";

my $new_conn;

while (<$sock>) {
    last if /^(\.|END)/;
    $new_conn = $_;
}

$new_conn = get_conn_id($new_conn);

print $sock "close_conn $new_conn\r\n";
$res = <$sock>;
is($res, "OK\r\n", "Successfully closd a connection");

print $new_sock "stats conns\r\n";
$res = <$new_sock>;
is($res,undef, "New connection is closed");

sub get_conn_id {
    my ($conn) = @_;
    $conn  =(split(':', $conn))[0];
    $conn =~ s/[^0-9]//g;
    return $conn;
}

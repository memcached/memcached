#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Select;
use IO::Socket qw(AF_INET SOCK_STREAM);

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

# Set up some server sockets.
sub mock_server {
    my $port = shift;
    my $srv = IO::Socket->new(
        Domain => AF_INET,
        Type => SOCK_STREAM,
        Proto => 'tcp',
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        ReusePort => 1,
        Listen => 5) || die "IO::Socket: $@";
    return $srv;
}

sub accept_backend {
    my $srv = shift;
    my $be = $srv->accept();
    $be->autoflush(1);
    ok(defined $be, "mock backend created");
    like(<$be>, qr/version/, "received version command");
    print $be "VERSION 1.0.0-mock\r\n";

    return $be;
}

# Put a version command down the pipe to ensure the socket is clear.
# client version commands skip the proxy code
sub check_version {
    my $ps = shift;
    print $ps "version\r\n";
    like(<$ps>, qr/VERSION /, "version received");
}

sub wait_reload {
    my $w = shift;
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
}

# We just need a single backend here; there's no logical difference if it's in
# a cluster or not.
note "making mock servers";
my $msrv = mock_server(11799);

# Start up a clean server.
my $p_srv = new_memcached('-o proxy_config=./t/proxyantiflap.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

{
    my $watcher = $p_srv->new_sock;
    print $watcher "watch proxyevents\n";
    is(<$watcher>, "OK\r\n", "watcher enabled");

    my $be = accept_backend($msrv);
    my $s = IO::Select->new();
    $s->add($be);

    # Make some backend requests but refuse to answer.
    for (1 .. 3) {
        print $ps "mg foo\r\n";
        # Block until we error and reconnect.
        is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "request cancelled");
        like(<$watcher>, qr/error=timeout/, "timeout error log");
        $be = accept_backend($msrv);
    }
    print $ps "mg bar\r\n";
    # Block until we error and reconnect.
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "request cancelled");
    $be = accept_backend($msrv);
    like(<$watcher>, qr/error=markedbadflap name=\S+ port=\S+ label=b\d+ retry=1/, "got caught flapping");

    print $ps "mg baz\r\n";
    is(scalar <$be>, "mg baz\r\n", "backend does reconnect and still works");
    print $be "HD\r\n";
    is(scalar <$ps>, "HD\r\n", "client still works post-flap");

    # clear error logs.
    like(<$watcher>, qr/error=timeout/, "timeout error log");
    like(<$watcher>, qr/error=markedbadflap name=\S+ port=\S+ label=b\d+ retry=2/, "re-flapped, longer retry");
    $p_srv->reload();
    wait_reload($watcher);

    # Hold the previous backend so its descriptor doesn't log
    my $oldbe = $be;

    # This should reset the flap counter as the backend description changes.
    $be = accept_backend($msrv);

    check_version($ps);

    # Make some backend requests but refuse to answer.
    for (1 .. 3) {
        print $ps "mg foo\r\n";
        # Block until we error and reconnect.
        is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "request cancelled");
        like(<$watcher>, qr/error=timeout/, "timeout error log");
        $be = accept_backend($msrv);
    }
    print $ps "mg bar\r\n";
    # Block until we error and reconnect.
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "request cancelled");
    like(<$watcher>, qr/error=markedbadflap/, "got caught flapping");

    $be = accept_backend($msrv);

    like(<$watcher>, qr/error=timeout/, "previous backend goes away");
    like(<$watcher>, qr/error=markedbadflap/, "still considered flapping");
    check_version($ps);

    # verify the new backend works.
    print $ps "mg baz\r\n";
    is(scalar <$be>, "mg baz\r\n", "backend does work");
    print $be "HD\r\n";
    is(scalar <$ps>, "HD\r\n", "client still works");

    # Now wait and see if the next failure causes a flap or not.
    sleep 3;

    print $ps "mg bar\r\n";
    # Block until we error and reconnect.
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "request cancelled");

    like(<$watcher>, qr/error=timeout/, "normal timeout error");
    # This will pause until readvalidate fails, so we can be sure a flap error
    # didn't follow the timeout error.
    unlike(<$watcher>, qr/error=markedbadflap/, "didn't flap again");
}

done_testing();

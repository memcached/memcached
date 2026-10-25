#!/usr/bin/env perl

# -o proxy_drain_timeout: on SIGTERM the proxy stops accepting connections
# and waits for in-flight requests, including background requests that were
# already answered to the client, before it exits.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Select;
use Time::HiRes;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $t = Memcached::ProxyTest->new(servers => [12201]);

sub start_proxy {
    my $opts = shift;
    my $srv = new_memcached("-o proxy_config=./t/proxydrain.lua$opts -t 1");
    my $ps = $srv->sock;
    $ps->autoflush(1);
    $t->set_c($ps);
    $t->accept_backends();
    return $srv;
}

# start a background request: the client gets its answer, the backend
# gets the request and doesn't answer yet.
sub start_background {
    my ($srv, $key) = @_;
    $t->c_send("mg $key\r\n");
    $t->c_recv("HD\r\n", "client answered");
    $t->be_recv(0, "mg $key\r\n", "backend received the request");
}

sub active {
    my $srv = shift;
    return mem_stats($srv->new_sock)->{proxy_req_active};
}

# seconds until the process exits, or undef if it is still running after
# $max seconds.
sub wait_exit {
    my ($srv, $max) = @_;
    my $start = Time::HiRes::time();
    while (Time::HiRes::time() - $start < $max) {
        return Time::HiRes::time() - $start unless $srv->is_running();
        Time::HiRes::sleep(0.05);
    }
    return undef;
}

sub can_connect {
    my $srv = shift;
    return defined $srv->new_sock ? 1 : 0;
}

subtest 'drain off by default' => sub {
    my $srv = start_proxy('');
    start_background($srv, "default");
    is(active($srv), 1, "one request in flight");
    $srv->stop();
    ok(defined wait_exit($srv, 5), "exited without waiting for the backend");
};

subtest 'drain waits for background requests' => sub {
    my $srv = start_proxy(',proxy_drain_timeout=10');
    start_background($srv, "first");
    is(active($srv), 1, "one request in flight");

    $srv->stop();
    # the main thread picks the signal up on its once-a-second tick.
    Time::HiRes::sleep(1.5);
    ok($srv->is_running(), "still running while a request is in flight");
    ok(!can_connect($srv), "listener closed");

    # established client connections are still served.
    start_background($srv, "second");

    $t->be_send(0, "HD\r\n");
    $t->be_send(0, "HD\r\n");
    my $took = wait_exit($srv, 5);
    ok(defined $took, "exited once the backend answered");
};

subtest 'drain gives up after the timeout' => sub {
    my $srv = start_proxy(',proxy_drain_timeout=1');
    start_background($srv, "stuck");
    $srv->stop();
    my $took = wait_exit($srv, 5);
    ok(defined $took, "exited although the backend never answered");
};

subtest 'second signal skips the drain' => sub {
    my $srv = start_proxy(',proxy_drain_timeout=30');
    start_background($srv, "stuck");
    $srv->stop();
    Time::HiRes::sleep(1.5);
    ok($srv->is_running(), "draining");
    $srv->stop();
    ok(defined wait_exit($srv, 5), "exited on the second signal");
};

done_testing();

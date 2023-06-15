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

my @mocksrvs = ();
note "making mock servers";
for my $port (11711, 11712, 11713) {
    my $srv = mock_server($port);
    ok(defined $srv, "mock server created");
    push(@mocksrvs, $srv);
}

# Start up a clean server.
# Since limits are per worker thread, cut the worker threads down to 1 to ease
# testing.
my $p_srv = new_memcached('-o proxy_config=./t/proxylimits.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);
my @mbe = ();
my $watcher;

{
    for my $msrv ($mocksrvs[0], $mocksrvs[1], $mocksrvs[2]) {
        my $be = accept_backend($msrv);
        push(@mbe, $be);
    }

    my $stats = mem_stats($ps, 'proxy');
    isnt($stats->{active_req_limit}, 0, "active request limit is set");

    # active request limit is 4, pipeline 6 requests and ensure the last two
    # get junked
    my $cmd = '';
    for ('a', 'b', 'c', 'd', 'e', 'f') {
        $cmd .= "mg /test/$_\r\n";
    }
    print $ps $cmd;

    # Lua config only sends commands to the first backend for this test.
    my $be = $mbe[0];
    for (1 .. 4) {
        like(<$be>, qr/^mg \/test\/\w\r\n$/, "backend received mg");
        print $be "EN\r\n";
    }
    my $s = IO::Select->new();
    $s->add($be);
    my @readable = $s->can_read(0.25);
    is(scalar @readable, 0, "no more pending reads on backend");

    for (1 .. 4) {
        is(scalar <$ps>, "EN\r\n", "received miss from backend");
    }

    is(scalar <$ps>, "SERVER_ERROR active request limit reached\r\n", "got error back");
    is(scalar <$ps>, "SERVER_ERROR active request limit reached\r\n", "got two limit errors");

    # Test turning the limit back off.
    $watcher = $p_srv->new_sock;
    print $watcher "watch proxyevents\n";
    is(<$watcher>, "OK\r\n", "watcher enabled");
    $p_srv->reload();
    wait_reload($watcher);

    $stats = mem_stats($ps, 'proxy');
    is($stats->{active_req_limit}, 0, "active request limit unset");

    $cmd = '';
    for ('a', 'b', 'c', 'd', 'e', 'f') {
        $cmd .= "mg /test/$_\r\n";
    }
    print $ps $cmd;
    for (1 .. 6) {
        like(<$be>, qr/^mg \/test\/\w\r\n$/, "backend received mg");
        print $be "EN\r\n";
    }
    for (1 .. 6) {
        is(scalar <$ps>, "EN\r\n", "received miss from backend");
    }
}

{
    # Test the buffer memory limiter.
    # - limit per worker will be 1/t global limit
    $p_srv->reload();
    wait_reload($watcher);
    # Get a secondary client to trample limit.
    my $sps = $p_srv->new_sock;

    my $stats = mem_stats($ps, 'proxy');
    isnt($stats->{buffer_memory_limit}, 0, "buf mem limit is set");

    # - test SET commands with values, but nothing being read on backend
    my $data = 'x' x 30000;
    my $cmd = "ms foo 30000 T30\r\n" . $data . "\r\n";
    print $ps $cmd;

    my $be = $mbe[0];
    my $s = IO::Select->new;
    $s->add($be);
    # Wait until the backend has the request queued, then send the second one.
    my @readable = $s->can_read(1);
    print $sps $cmd;

    my $res;
    is(scalar <$be>, "ms foo 30000 T30\r\n", "received first ms");
    $res = scalar <$be>;
    print $be "HD\r\n";

    # The second request should have been caught by the memory limiter
    is(scalar <$sps>, "SERVER_ERROR out of memory\r\n", "got server error");
    # FIXME: The original response cannot succeed because we cannot allocate
    # enough memory to read the response from the backend.
    # This is conveniently testing both paths right here but I would prefer
    # something better.
    # TODO: need to see if it's possible to surface an OOM from the backend
    # handler, but that requires more rewiring.
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "first request succeeded");

    # Backend gets killed from a read OOM, so we need to re-establish.
    $be = $mbe[0] = accept_backend($mocksrvs[0]);
    like(<$watcher>, qr/error=outofmemory/, "OOM log line");

    # Memory limits won't drop until the garbage collectors run, which
    # requires a bit more push, so instead we raise the limits here so we can
    # retry from the pre-existing connections to test swallow mode.
    $p_srv->reload();
    wait_reload($watcher);

    # Test sending another request down both pipes to ensure they still work.
    $cmd = "ms foo 2 T30\r\nhi\r\n";
    print $ps $cmd;
    is(scalar <$be>, "ms foo 2 T30\r\n", "client works after oom");
    is(scalar <$be>, "hi\r\n", "client works after oom");
    print $be "HD\r\n";
    is(scalar <$ps>, "HD\r\n", "client received resp after oom");
    print $sps $cmd;
    is(scalar <$be>, "ms foo 2 T30\r\n", "client works after oom");
    is(scalar <$be>, "hi\r\n", "client works after oom");
    print $be "HD\r\n";
    is(scalar <$sps>, "HD\r\n", "client received resp after oom");

    # - test disabling the limiter
    $stats = mem_stats($ps, 'proxy');
    isnt($stats->{buffer_memory_limit}, 0, "buf mem limit is set");
    $p_srv->reload();
    wait_reload($watcher);

    $stats = mem_stats($ps, 'proxy');
    is($stats->{buffer_memory_limit}, 0, "buf mem limit is not set");

    # - test GET commands but don't read back, large backend values
    # extended testing:
    # - create errors while holding the buffers?
}

check_version($ps);

{
    note "test memory used counter";
    my $be = $mbe[0];

    my $stats = mem_stats($ps, 'proxy');
    my $used = $stats->{buffer_memory_used};
    cmp_ok($used, '<', 1000, 'pre: buffer memory usage not inflated');

    my $cmd = "get foo\r\n";
    for (1 .. 100) {
        print $ps $cmd;
        {
            my $res = scalar <$be>;
            print $be "VALUE foo 0 2\r\nhi\r\n";
            print $be "END\r\n";
        }
        my $res = scalar <$ps>;
        $res = scalar <$ps>;
        $res = scalar <$ps>;
    }

    $stats = mem_stats($ps, 'proxy');
    $used = $stats->{buffer_memory_used};
    cmp_ok($used, '<', 1000, 'mid: buffer memory usage not inflated');

    my $cmd = "get foo foo foo foo\r\n";
    for (1 .. 50) {
        print $ps $cmd;
        for (1 .. 4) {
            my $res = scalar <$be>;
            print $be "VALUE foo 0 2\r\nhi\r\n";
            print $be "END\r\n";
        }
        for (1 .. 4) {
            my $res = scalar <$ps>;
            $res = scalar <$ps>;
        }
        # END
        my $res = scalar <$ps>;
    }

    $stats = mem_stats($ps, 'proxy');
    $used = $stats->{buffer_memory_used};
    cmp_ok($used, '<', 1000, 'multiget: buffer memory usage not inflated');

    my $cmd = "get foo\r\n";
    for (1 .. 200) {
        print $ps $cmd;
        {
            my $res = scalar <$be>;
            print $be "VALUE foo 0 2\r\nhi\r\n";
            print $be "END\r\n";
        }
        my $res = scalar <$ps>;
        $res = scalar <$ps>;
        $res = scalar <$ps>;
    }

    $stats = mem_stats($ps, 'proxy');
    $used = $stats->{buffer_memory_used};
    cmp_ok($used, '<', 1000, 'post: buffer memory usage not inflated');
}

# TODO:
# check reqlimit/bwlimit counters

done_testing();

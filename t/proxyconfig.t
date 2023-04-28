#!/usr/bin/env perl

# NOTE: These tests cover the act of reloading the configuration; changing
# backends, pools, routes, etc. It doesn't cover ensuring the code of the main
# file changes naturally, which is fine: there isn't any real way that can
# fail and it can be covered specifically in a different test file.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Select;
use IO::Socket qw(AF_INET SOCK_STREAM);

# TODO: possibly... set env var to a generated temp filename before starting
# the server so we can pass that in?
my $modefile = "/tmp/proxyconfigmode.lua";

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

sub write_modefile {
    my $cmd = shift;
    open(my $fh, "> $modefile") or die "Couldn't overwrite $modefile: $!";
    print $fh $cmd;
    close($fh);
}

sub wait_reload {
    my $w = shift;
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
}

my @mocksrvs = ();
#diag "making mock servers";
for my $port (11511, 11512, 11513) {
    my $srv = mock_server($port);
    ok(defined $srv, "mock server created");
    push(@mocksrvs, $srv);
}

diag "testing failure to start";
write_modefile("invalid syntax");
eval {
    my $p_srv = new_memcached('-o proxy_config=./t/proxyconfig.lua');
};
ok($@ && $@ =~ m/Failed to connect/, "server successfully not started");

write_modefile('return "none"');
my $p_srv = new_memcached('-o proxy_config=./t/proxyconfig.lua');
my $ps = $p_srv->sock;
$ps->autoflush(1);

# Create a watcher so we can monitor when reloads complete.
my $watcher = $p_srv->new_sock;
print $watcher "watch proxyevents\n";
is(<$watcher>, "OK\r\n", "watcher enabled");

{
    # test with stubbed main routes.
    print $ps "mg foo v\r\n";
    is(scalar <$ps>, "SERVER_ERROR no mg route\r\n", "no mg route loaded");
}

# Load some backends
{
    write_modefile('return "start"');

    $p_srv->reload();
    wait_reload($watcher);
}

my @mbe = ();
# A map of where keys route to for worker IO tests later
my %keymap = ();
my $keycount = 100;
{
    # set up server backend sockets.
    my $s = IO::Select->new();
    for my $msrv ($mocksrvs[0], $mocksrvs[1], $mocksrvs[2]) {
        my $be = accept_backend($msrv);
        $s->add($be);
        push(@mbe, $be);
    }

    # Try sending something.
    my $cmd = "mg foo v\r\n";
    print $ps $cmd;
    my @readable = $s->can_read(0.25);
    is(scalar @readable, 1, "only one backend became readable after mg");
    my $be = shift @readable;
    is(scalar <$be>, $cmd, "metaget passthrough");
    print $be "EN\r\n";
    is(scalar <$ps>, "EN\r\n", "miss received");

    # Route a bunch of keys and map them to backends.
    for my $key (0 .. $keycount) {
        print $ps "mg /test/$key\r\n";
        my @readable = $s->can_read(0.25);
        is(scalar @readable, 1, "only one backend became readable for this key");
        my $be = shift @readable;
        for (0 .. 2) {
            if ($be == $mbe[$_]) {
                $keymap{$key} = $_;
            }
        }
        is(scalar <$be>, "mg /test/$key\r\n", "got mg passthrough");
        print $be "EN\r\n";
        is(scalar <$ps>, "EN\r\n", "miss received");
    }
}

# Test backend table arguments and per-backend time overrides
my @holdbe = (); # avoid having the backends immediately disconnect and pollute log lines.
{
    # This should create three new backend sockets
    write_modefile('return "betable"');
    $p_srv->reload();
    wait_reload($watcher);

    my $watch_s = IO::Select->new();
    $watch_s->add($watcher);

    my $s = IO::Select->new();
    for my $msrv (@mocksrvs) {
        $s->add($msrv);
    }
    my @readable = $s->can_read(0.25);
    # All three backends should have changed despite having the same label,
    # host, and port arguments.
    is(scalar @readable, 3, "all listeners became readable");

    my @watchable = $watch_s->can_read(5);
    is(scalar @watchable, 1, "got new watcher log lines");
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_backend error=readvalidate name=\S+ port=11511/, "one backend timed out connecting");
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_backend error=markedbad name=\S+ port=11511/, "backend was marked bad");

    for my $msrv (@readable) {
        my $be = accept_backend($msrv);
        push(@holdbe, $be);
    }

    # reload again and ensure no sockets become readable
    $p_srv->reload();
    wait_reload($watcher);
    @readable = $s->can_read(0.5);
    is(scalar @readable, 0, "no new sockets");
}

# Disconnect the existing sockets
@mbe = ();
@holdbe = ();
@mocksrvs = ();
$watcher = $p_srv->new_sock;
# Reset the watcher and let logs die off.
sleep 1;
print $watcher "watch proxyevents\n";
is(<$watcher>, "OK\r\n", "watcher enabled");

{
    # re-create the mock servers so we get clean connects, the previous
    # backends could be reconnecting still.
    for my $port (11514, 11515, 11516) {
        my $srv = mock_server($port);
        ok(defined $srv, "mock server created");
        push(@mocksrvs, $srv);
    }

    write_modefile('return "noiothread"');
    $p_srv->reload();
    wait_reload($watcher);

    my $s = IO::Select->new();
    for my $msrv (@mocksrvs) {
        $s->add($msrv);
    }
    my @readable = $s->can_read(0.25);
    # All three backends should become readable with new sockets.
    is(scalar @readable, 3, "all listeners became readable");

    my @bepile = ();
    my $bes = IO::Select->new(); # selector just for the backend sockets.
    # Each backend should create one socket per worker thread.
    for my $msrv (@readable) {
        my @temp = ();
        for (0 .. 3) {
            my $be = accept_backend($msrv);
            $bes->add($be);
            push(@temp, $be);
        }
        for (0 .. 2) {
            if ($mocksrvs[$_] == $msrv) {
                $bepile[$_] = \@temp;
            }
        }
    }

    # clients round robin onto different worker threads, so we can test the
    # key dist on different offsets.
    my @cli = ();
    for (0 .. 2) {
        my $p = $p_srv->new_sock;

        for my $key (0 .. $keycount) {
            print $p "mg /test/$key\r\n";
            @readable = $bes->can_read(0.25);
            is(scalar @readable, 1, "only one backend became readable");
            my $be = shift @readable;
            # find which listener this be belongs to
            for my $x (0 .. 2) {
                for (@{$bepile[$x]}) {
                    if ($_ == $be) {
                        cmp_ok($x, '==', $keymap{$key}, "key routed to correct listener: " . $keymap{$key});
                    }
                }
            }

            is(scalar <$be>, "mg /test/$key\r\n", "got mg passthrough");
            print $be "EN\r\n";
            is(scalar <$p>, "EN\r\n", "miss received");
        }

        # hold onto the sockets just in case.
        push(@cli, $p);
    }

    @readable = $s->can_read(0.25);
    is(scalar @readable, 0, "no listeners should be active pre-reload");
    $p_srv->reload();
    wait_reload($watcher);
    @readable = $s->can_read(0.25);
    is(scalar @readable, 0, "no listeners should be active post-reload");
}

###
# diag "starting proxy again from scratch"
###

# TODO: probably time to abstract the entire "start the server with mocked
# listeners" routine.
$watcher = undef;
write_modefile('return "reqlimit"');
$p_srv->stop;
while (1) {
    if ($p_srv->is_running) {
        sleep 1;
    } else {
        ok(!$p_srv->is_running, "stopped proxy");
        last;
    }
}

@mocksrvs = ();
# re-create the mock servers so we get clean connects, the previous
# backends could be reconnecting still.
for my $port (11511, 11512, 11513) {
    my $srv = mock_server($port);
    ok(defined $srv, "mock server created");
    push(@mocksrvs, $srv);
}

# Start up a clean server.
# Since limits are per worker thread, cut the worker threads down to 1 to ease
# testing.
$p_srv = new_memcached('-o proxy_config=./t/proxyconfig.lua -t 1');
$ps = $p_srv->sock;
$ps->autoflush(1);

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
    write_modefile('return "noreqlimit"');
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
    write_modefile('return "buflimit"');
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
    write_modefile('return "buflimit2"');
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

    # - test GET commands but don't read back, large backend values
    # - test disabling the limiter
    # extended testing:
    # - create errors while holding the buffers?
}

# TODO:
# check reqlimit/bwlimit counters
# remove backends
# do dead sockets close?
# adding user stats
# changing user stats
# adding backends with the same label don't create more connections
# total backend counters
# change top level routes mid-request
#  - send the request to backend
#  - issue and wait for reload
#  - read from backend and respond, should use the original code still.
#  - could also read from backend and then do reload/etc.

done_testing();

END {
    unlink $modefile;
}

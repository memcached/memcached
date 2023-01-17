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

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

# TODO: possibly... set env var to a generated temp filename before starting
# the server so we can pass that in?
my $modefile = "/tmp/proxyconfigmode.lua";

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
diag "making mock servers";
for my $port (11511, 11512, 11513, 11514, 11515, 11516) {
    my $srv = mock_server($port);
    ok(defined $srv, "mock server created");
    push(@mocksrvs, $srv);
}

diag "testing failure to start";
write_modefile("invalid syntax");
eval {
    my $p_srv = new_memcached('-o proxy_config=./t/proxyconfig.lua -l 127.0.0.1', 11510);
};
ok($@ && $@ =~ m/Failed to connect/, "server successfully not started");

write_modefile('return "none"');
my $p_srv = new_memcached('-o proxy_config=./t/proxyconfig.lua -l 127.0.0.1', 11510);
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

{
    # set up server backend sockets.
    my @mbe = ();
    for my $msrv ($mocksrvs[0], $mocksrvs[1], $mocksrvs[2]) {
        my $be = $msrv->accept();
        $be->autoflush(1);
        ok(defined $be, "mock backend created");
        push(@mbe, $be);
    }

    my $s = IO::Select->new();

    for my $be (@mbe) {
        $s->add($be);
        like(<$be>, qr/version/, "received version command");
        print $be "VERSION 1.0.0-mock\r\n";
    }

    # Try sending something.
    my $cmd = "mg foo v\r\n";
    print $ps $cmd;
    my @readable = $s->can_read(1);
    is(scalar @readable, 1, "only one backend became readable");
    my $be = shift @readable;
    is(scalar <$be>, $cmd, "metaget passthrough");
    print $be "EN\r\n";
    is(scalar <$ps>, "EN\r\n", "miss received");
}

# TODO:
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

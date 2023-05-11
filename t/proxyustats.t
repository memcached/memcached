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

# TODO: possibly... set env var to a generated temp filename before starting
# the server so we can pass that in?
my $configfile = "/tmp/proxyustats.lua";

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

# A single line containing prefix, start ustat and end ustat index.
sub write_config {
    my $cmd = shift;
    open(my $fh, "> $configfile") or die "Couldn't overwrite $configfile: $!";
    print $fh $cmd;
    close($fh);
}

sub wait_reload {
    my $w = shift;
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
}

my ($p_srv, $ps, $watcher);
sub restart_memcached {
    if ($p_srv) {
        $p_srv->stop();
    }
    write_config('return "a 1 0"');
    $p_srv = new_memcached('-o proxy_config=./t/proxyustats.lua');
    $ps = $p_srv->sock;
    $ps->autoflush(1);

    $watcher = $p_srv->new_sock;
    print $watcher "watch proxyevents\n";
    is(<$watcher>, "OK\r\n", "watcher enabled");
}

diag "testing failure to start";
write_config("invalid");
eval {
    $p_srv = new_memcached('-o proxy_config=./t/proxyustats.lua');
};
ok($@ && $@ =~ m/Failed to connect/, "server successfully not started");

restart_memcached();

subtest 'succeeded to allocate 1024 ustats' => sub {
    my $pfx = "a";
    my $first = 1;
    my $last = 1024;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    wait_reload($watcher);

    my $stats = mem_stats($ps, 'proxy');
    for my $i ($first..$last) {
        my $ustat = "user_" . $pfx . $i;
        is($stats->{$ustat}, 0, $ustat . " found");
    }
};

subtest 'failed to allocate 1025 ustats' => sub {
    my $pfx = "a";
    my $first = 1025;
    my $last = 1025;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    unlike(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload not started");
    unlike(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload not completed");

    restart_memcached();
};

subtest 'failed to allocate ustat at index 0' => sub {
    my $pfx = "a";
    my $first = 0;
    my $last = 0;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    unlike(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload not started");
    unlike(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload not completed");

    restart_memcached();
};


subtest 'succeeded to allocate ustat at 1024 only' => sub {
    # restart memcached to clear any ustats.
    restart_memcached();

    my $pfx = "a";
    my $first = 1024;
    my $last = 1024;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    wait_reload($watcher);

    my $stats = mem_stats($ps, 'proxy');
    while (my ($ustat, $value) = each %{$stats}) {
        if (index($ustat, "user_") == 0) {
            is($ustat, "user_a1024", "user_a1024 found");
        }
    }
};

subtest 'ustats incr/decr and perseverance over reload' => sub {
    # restart memcached to clear any ustats.
    restart_memcached();

    my $pfx = "a";
    my $first = 1;
    my $last = 3;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    wait_reload($watcher);

    print $ps "mg 1\r\n";
    is(scalar <$ps>, "HD\r\n", "mg 1 hit");
    print $ps "mg 2\r\n";
    is(scalar <$ps>, "HD\r\n", "mg 2 hit");
    print $ps "mg 2\r\n";
    is(scalar <$ps>, "HD\r\n", "mg 2 hit");

    my $stats = mem_stats($ps, 'proxy');
    is($stats->{user_a1}, 1, "user_a1 is 1");
    is($stats->{user_a2}, 4, "user_a2 is 4");
    is($stats->{user_a3}, 0, "user_a3 is 0");

    $pfx = "b";
    $first = 2;
    $last = 4;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    wait_reload($watcher);

    # subtract 2 at idx 2.
    print $ps "mg -2\r\n";
    is(scalar <$ps>, "HD\r\n", "mg -2 hit");

    $stats = mem_stats($ps, 'proxy');
    is($stats->{user_a1}, 1, "user_a1 is 1");
    is($stats->{user_b2}, 2, "user_b2 is 2");
    is($stats->{user_b3}, 0, "user_b3 is 0");
    is($stats->{user_b4}, 0, "user_b4 is 0");
};

subtest 'failed to allocate ustat longer than 128 chars' => sub {
    my $pfx = '*' x 128;
    my $first = 1;
    my $last = 1;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    unlike(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload not started");
    unlike(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload not completed");

    restart_memcached();
};

subtest 'negative ustat value underflow' => sub {
    # restart memcached to clear any ustats.
    restart_memcached();

    my $pfx = "a";
    my $first = 1;
    my $last = 1;
    write_config('return "' . $pfx . ' ' . $first . ' ' . $last . '"');
    $p_srv->reload();
    wait_reload($watcher);

    print $ps "mg -1\r\n";
    is(scalar <$ps>, "HD\r\n", "mg -1 hit");

    my $stats = mem_stats($ps, 'proxy');
    isnt($stats->{user_a1}, -1, "user_a1 is not -1");
};

done_testing();

END {
    unlink $configfile;
}

#!/usr/bin/env perl

# A SIGHUP that arrives while the config thread is busy (here: in the
# middle of another reload) must still cause a reload once it is free.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use Time::HiRes;

my $configfile = "/tmp/proxyreloadbusy.lua";

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

sub write_config {
    my $cmd = shift;
    open(my $fh, "> $configfile") or die "Couldn't overwrite $configfile: $!";
    print $fh $cmd;
    close($fh);
}

write_config('return "first 0"');
my $p_srv = new_memcached('-o proxy_config=./t/proxyreloadbusy.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

my $watcher = $p_srv->new_sock;
print $watcher "watch proxyevents\n";
is(<$watcher>, "OK\r\n", "watcher enabled");

# a lost reload never logs anything: don't block forever on the watcher.
sub next_event {
    my $line = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(10);
        my $l = <$watcher>;
        alarm(0);
        $l;
    };
    return defined $line ? $line : "timed out\n";
}

sub wait_reload {
    like(next_event(), qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(next_event(), qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
}

sub check_route {
    my $name = shift;
    print $ps "mg foo\r\n";
    is(scalar <$ps>, "SERVER_ERROR $name\r\n", "routed by the '$name' config");
}

check_route("first");

subtest 'SIGHUP during a reload is not lost' => sub {
    write_config('return "slow 2.5"');
    $p_srv->reload();
    like(next_event(), qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "slow reload started");

    # signals are picked up on the main thread's once-a-second clock tick,
    # so give it time to try (and fail) to take the config lock.
    write_config('return "second 0"');
    Time::HiRes::sleep(0.5);
    $p_srv->reload();
    like(next_event(), qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "slow reload completed");

    # the second request has to run after the slow one.
    wait_reload();
    check_route("second");
};

done_testing();

END {
    unlink $configfile;
}

#!/usr/bin/env perl
# Regression test: graceful shutdown must not hang in logger_stop() when the
# logger thread has just reaped the last watcher (lost wakeup on
# logger_stack_cond). Timing-based; without the fix it hangs in most runs.

use strict;
use warnings;
use Test::More;
use Time::HiRes ();
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

for my $round (1..2) {
    my $server = new_memcached("-A");
    my $sock = $server->sock;

    my $watcher = $server->new_sock;
    print $watcher "watch\r\n";
    is(scalar <$watcher>, "OK\r\n", "round $round: watcher attached");

    # Let the logger back off towards its maximum sleep with no traffic.
    Time::HiRes::sleep(8);
    close($watcher);
    Time::HiRes::sleep(0.3);

    print $sock "shutdown graceful\r\n";
    my $stopped = 0;
    for (1..100) {
        if (!$server->is_running) { $stopped = 1; last; }
        Time::HiRes::sleep(0.1);
    }
    ok($stopped, "round $round: graceful shutdown completed after last watcher left");
    unless ($stopped) {
        # A hung server ignores SIGINT/SIGTERM (the handler only sets a flag).
        # timedrun escalates to SIGKILL after repeated signals; wait for it so
        # no hung process is left behind.
        kill 'TERM', $server->{pid};
        for (1..150) { last unless $server->is_running; Time::HiRes::sleep(0.1); }
    }
}

done_testing();

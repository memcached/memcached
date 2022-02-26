#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# Disabled shutdown (default)
{
    my $server = new_memcached();
    my $sock = $server->sock;
    print $sock "shutdown\r\n";
    is(scalar <$sock>, "ERROR: shutdown not enabled\r\n",
        "error when shutdown is not enabled");
}

# Shutdown command error
{
    my$server = new_memcached("-A");
    my $sock = $server->sock;
    print $sock "shutdown foo\r\n";
    like(scalar <$sock>, qr/CLIENT_ERROR/, "rejected invalid shutdown mode");
}

# Normal shutdown
{
    my $server = new_memcached("-A");
    my $sock = $server->sock;
    print $sock "version\r\n";
    like(scalar <$sock>, qr/VERSION/, "server is initially alive");
    print $sock "shutdown\r\n";
    still_going($server);
}

# Graceful shutdown
{
    my $server = new_memcached("-A");
    my $sock = $server->sock;
    print $sock "version\r\n";
    like(scalar <$sock>, qr/VERSION/, "server is initially alive");
    print $sock "shutdown graceful\r\n";
    still_going($server);
}

sub still_going {
    my $server = shift;
    for (1..10) {
        if ($server->is_running) {
            sleep 1;
        } else {
            ok(!$server->is_running, "server stopped");
            return;
        }
    }

    ok(0, "server failed to stop");
}

done_testing();

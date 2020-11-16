#!/usr/bin/perl

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
    print $sock "version\r\n";
    is(scalar <$sock>, undef, "server has been normally shut down");
}

# Graceful shutdown
{
    my $server = new_memcached("-A");
    my $sock = $server->sock;
    print $sock "version\r\n";
    like(scalar <$sock>, qr/VERSION/, "server is initially alive");
    print $sock "shutdown graceful\r\n";
    print $sock "version\r\n";
    is(scalar <$sock>, undef, "server has been gracefully shut down");
}

done_testing();

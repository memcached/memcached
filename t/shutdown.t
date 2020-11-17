#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server;
my $sock;

# Disabled shutdown (default)
$server = new_memcached();
$sock = $server->sock;
print $sock "shutdown\r\n";
is(scalar <$sock>, "ERROR: shutdown not enabled\r\n",
    "error when shutdown is not enabled");
$server->DESTROY();

# Shutdown command error
$server = new_memcached("-A");
$sock = $server->sock;
print $sock "shutdown foo\r\n";
like(scalar <$sock>, qr/CLIENT_ERROR/, "rejected invalid shutdown mode");
$server->DESTROY();

# Normal shutdown
$server = new_memcached("-A");
$sock = $server->sock;
print $sock "version\r\n";
like(scalar <$sock>, qr/VERSION/, "server is initially alive");
print $sock "shutdown\r\n";
print $sock "version\r\n";
is(scalar <$sock>, undef, "server has been normally shut down");

# Graceful shutdown
$server = new_memcached("-A");
$sock = $server->sock;
print $sock "version\r\n";
like(scalar <$sock>, qr/VERSION/, "server is initially alive");
print $sock "shutdown graceful\r\n";
print $sock "version\r\n";
is(scalar <$sock>, undef, "server has been gracefully shut down");

done_testing();

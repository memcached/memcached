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

# Normal shutdown
$server = new_memcached("-A");
$sock = $server->sock;
print $sock "version\r\n";
like(scalar <$sock>, qr/VERSION/, "server is alive");
print $sock "shutdown\r\n";
print $sock "version\r\n";
is(scalar <$sock>, undef, "server has been shut down");

# Graceful shutdown
$server = new_memcached("-A");
$sock = $server->sock;
print $sock "version\r\n";
like(scalar <$sock>, qr/VERSION/, "server is alive");
print $sock "shutdown_graceful\r\n";
print $sock "version\r\n";
is(scalar <$sock>, undef, "server has been gracefully shut down");

done_testing();

#!/usr/bin/env perl

use strict;
use Test::More tests => 9;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# FIXME: Some tests are forcing UDP to be enabled via MemcachedTest.pm - need
# to audit and fix.
my $server = new_memcached("-Y $Bin/authfile -U 0");
my $sock = $server->sock;

# Test unauthenticated modes
print $sock "set foo 0 0 2\r\nhi\r\n";
like(scalar <$sock>, qr/CLIENT_ERROR/, "failed to do a write");
print $sock "get foo\r\n";
like(scalar <$sock>, qr/CLIENT_ERROR/, "failed to do a read");

# Fail to authenticate.
print $sock "set foo 0 0 7\r\nfoo bab\r\n";
like(scalar <$sock>, qr/CLIENT_ERROR/, "failed to authenticate");

# Try for real.
print $sock "set foo 0 0 7\r\nfoo bar\r\n";
like(scalar <$sock>, qr/STORED/, "authenticated?");

print $sock "set toast 0 0 2\r\nhi\r\n";
like(scalar <$sock>, qr/STORED/, "stored an item that didn't look like user/pass");

mem_get_is($sock, "toast", "hi");

# Create a second socket, try to authenticate against the second token.

my $sock2 = $server->new_sock;

print $sock2 "set foo 0 0 10\r\nbaaaz quux\r\n";
like(scalar <$sock2>, qr/STORED/, "authenticated a second socket?");

print $sock2 "set toast2 0 0 2\r\nho\r\n";
like(scalar <$sock2>, qr/STORED/, "stored an item that didn't look like user/pass");

mem_get_is($sock2, "toast2", "ho");

# TODO: tests for reloads.

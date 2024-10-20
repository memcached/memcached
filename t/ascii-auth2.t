#!/usr/bin/env perl
# Testing for single-line authfiles with no newline at the end.

use strict;
use Test::More tests => 4;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached("-Y $Bin/authfile2 -U 0");
my $sock = $server->sock;

# Fail to authenticate.
print $sock "set foo 0 0 7\r\nfoo bab\r\n";
like(scalar <$sock>, qr/CLIENT_ERROR/, "failed to authenticate");

# Try for real.
print $sock "set foo 0 0 7\r\nfoo bar\r\n";
like(scalar <$sock>, qr/STORED/, "authenticated?");

print $sock "set toast 0 0 2\r\nhi\r\n";
like(scalar <$sock>, qr/STORED/, "stored an item that didn't look like user/pass");

mem_get_is($sock, "toast", "hi");


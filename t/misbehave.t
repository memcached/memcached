#!/usr/bin/perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

if (supports_drop_priv()) {
    plan tests => 1;
} else {
    plan skip_all => 'Privilege drop not supported';
    exit 0;
}

my $server = new_memcached();
my $sock = $server->sock;

print $sock "misbehave\r\n";
is(scalar <$sock>, "OK\r\n", "did not allow misbehaving");

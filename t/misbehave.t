#!/usr/bin/perl

use strict;
use Test::More;
use FindBin qw($Bin);
use Socket qw(MSG_PEEK MSG_DONTWAIT);
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
sleep(1);

# check if the socket is dead now
my $buff;
my $ret = recv($sock, $buff, 1, MSG_PEEK | MSG_DONTWAIT);
is($ret, undef, "did not allow misbehaving");

$server->DESTROY();

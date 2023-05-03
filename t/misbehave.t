#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use Socket qw(MSG_PEEK MSG_DONTWAIT);
use lib "$Bin/lib";
use MemcachedTest;

if (!enabled_tls_testing() && supports_drop_priv()) {
    plan tests => 1;
} else {
    plan skip_all => 'Privilege drop not supported';
    exit 0;
}

my $server = new_memcached('-o drop_privileges');
my $sock = $server->sock;

print $sock "misbehave\r\n";
sleep(1);

# check if the socket is dead now
my $buff;
my $ret = recv($sock, $buff, 1, MSG_PEEK | MSG_DONTWAIT);
# ret = 0 means read 0 bytes, which means a closed socket
ok($ret == 0, "did not allow misbehaving");

$server->DESTROY();

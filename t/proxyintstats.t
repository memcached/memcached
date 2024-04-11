#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Socket qw(AF_INET SOCK_STREAM);
use IO::Select;
use Data::Dumper qw/Dumper/;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $p_srv = new_memcached('-o proxy_config=./t/proxyintstats.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

my $w = $p_srv->new_sock;
print $w "watch proxyuser\n";
is(<$w>, "OK\r\n", "watcher enabled");

# store one value so items/slabs has data.
print $ps "set foo 0 0 2\r\nhi\r\n";
is(scalar <$ps>, "STORED\r\n", "test value stored");

my @stats = qw/basic settings conns extstore proxy proxyfuncs proxybe items slabs/;

for my $st (@stats) {
    like(<$w>, qr/SUCCESS: $st/, "successfully ran $st");
}

pass("didn't crash");

done_testing();

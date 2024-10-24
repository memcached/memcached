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

my $t = Memcached::ProxyTest->new(servers => [12181]);

my $p_srv = new_memcached('-o proxy_config=routelib,proxy_arg=./t/proxyroutelib.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

my $w = $p_srv->new_sock;
print $w "watch proxyevents\r\n";
is(<$w>, "OK\r\n");

# We don't intend to test routelib here, just ensure that the embedding works
# and this obviously routelib config starts.

subtest 'basic' => sub {
    $t->c_send("mg test\r\n");
    $t->be_recv(0, "mg test\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();
};

done_testing();

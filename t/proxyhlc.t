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

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $t = Memcached::ProxyTest->new(servers => [19211]);
my $p_srv = new_memcached('-o proxy_config=./t/proxyhlc.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

subtest 'hlc pass through' => sub {
    $t->c_send("ms foo 2\r\nhi\r\n");
    $t->be_recv_like(0, qr/^ms foo 2 E[0-9]+/, "backend received client request");
    $t->be_recv(0, "hi\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be("client received HD");

    $t->c_send("mg foo c s\r\n");
    $t->be_recv_c(0);
    $t->be_send(0, "HD s2 c14335932268801950079\r\n");
    $t->c_recv_be("client received HLC-like response");
};

# TODO:
# - different flag ordering in request/response
# - check that opaque is what we expect it to be both inbound/outbound
# - check that two runs in a row gives an incrementing number
# what else? not a lot of ways this can fail due to lack of inputs.

done_testing();

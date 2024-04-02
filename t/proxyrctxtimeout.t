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

# Set up the listeners _before_ starting the proxy.
# the fourth listener is only occasionally used.
my $t = Memcached::ProxyTest->new(servers => [12141, 12142, 12143]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyrctxtimeout.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

subtest 'sleep' => sub {
    plan skip_all => 'sleep does not work';
    $t->c_send("mg sleep/foo t\r\n");
    $t->be_recv_c(0, "near got request");
    $t->be_send(0, "HD t94\r\n");
    $t->c_recv_be();
    $t->clear();
};

subtest 'no timeout' => sub {
    # first response is good
    $t->c_send("mg cond_timeout/foo\r\n");
    $t->be_recv_c(0);
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();
};

subtest 'first req times out' => sub {
    $t->c_send("mg cond_timeout/boo t\r\n");
    $t->be_recv_c([1,2], "far backends received requests");
    $t->be_recv_c(0, "near req still arrived");
    $t->be_send([1,2], "HD t90\r\n");
    $t->c_recv_be();
    # Should get eaten.
    $t->be_send(0, "HD t40\r\n");
    $t->clear();
};

subtest 'first req times out, but still returns' => sub {
    $t->c_send("mg cond_timeout/qoo t\r\n");
    $t->be_recv_c([1,2], "near timeout, far received req");
    $t->be_recv_c(0, "near received request");

    $t->be_send(0, "HD t14\r\n");
    $t->c_recv_be("near timed out but client got its response");
    # returned but doesn't go anywhere.
    $t->be_send([1,2], "HD t17\r\n");
    $t->clear();
};

subtest 'enqueue_timeout' => sub {
    $t->c_send("mg enqueue_timeout/foo t\r\n");
    $t->be_recv_c([1,2], "near timeout, far received req");
    $t->be_recv_c(0, "near req still arrived");
    $t->be_send([1,2], "HD t91\r\n");
    $t->c_recv_be();
    $t->be_send(0, "HD t15\r\n");
    $t->clear();
};

subtest 'enqueue_and_wait no timeout' => sub {
    $t->c_send("mg enqueue_timeout/foo t\r\n");
    $t->be_recv_c(0, "near req arrived");
    $t->be_send(0, "HD t16\r\n");
    $t->c_recv_be();
    $t->clear();
};

subtest 'handle_timeout' => sub {
    $t->c_send("mg handle_timeout/foo t\r\n");
    $t->be_recv_c([1,2], "near timeout, far received req");
    $t->be_recv_c(0, "near req still arrived");
    $t->be_send([1,2], "HD t92\r\n");
    $t->c_recv_be();
    $t->be_send(0, "HD t16\r\n");
    $t->clear();
};

subtest 'wait on the same handle twice' => sub {
    $t->c_send("mg wait_more/foo t\r\n");
    $t->be_recv_c(0, "near got request");
    # Let it internally time out.
    sleep 0.75;
    pass("short sleep");
    $t->be_send(0, "HD t93\r\n");
    $t->c_recv_be();
    $t->clear();
};

subtest 'wait handle no timeout' => sub {
    $t->c_send("mg wait_more/foo t\r\n");
    $t->be_recv_c(0, "near got request");
    $t->be_send(0, "HD t93\r\n");
    $t->c_recv("SERVER_ERROR no timeout\r\n", "client received SERVER_ERROR");
    $t->clear();
};

subtest 'wait double' => sub {
    $t->c_send("mg wait_double/foo t\r\n");
    $t->be_recv_c(0, "near got request");
    # Let it internally time out.
    sleep 0.75;
    pass("short sleep");
    $t->be_send(0, "HD t98\r\n");
    $t->c_recv_be();
    $t->clear();
};

done_testing();

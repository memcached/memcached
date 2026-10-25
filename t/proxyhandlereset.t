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

my $t = Memcached::ProxyTest->new(servers => [12211]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyhandlereset.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

sub active {
    return mem_stats($ps)->{proxy_req_active};
}

subtest 'same handle sent three times' => sub {
    for my $round (1 .. 3) {
        $t->c_send("mg retry/$round v\r\n");
        $t->be_recv(0, "mg retry/$round v\r\n", "attempt 1");
        $t->be_send(0, "SERVER_ERROR busy\r\n");
        $t->be_recv(0, "mg retry/$round v\r\n", "attempt 2 on the same handle");
        $t->be_send(0, "SERVER_ERROR busy\r\n");
        $t->be_recv(0, "mg retry/$round v\r\n", "attempt 3 on the same handle");
        $t->be_send(0, "VA 2\r\nhi\r\n");
        $t->c_recv("VA 2\r\n", "client got the third result");
        $t->c_recv("hi\r\n");
        $t->clear();
    }
    is(active(), 0, "no request left active");
};

subtest 'a good first result is not retried' => sub {
    $t->c_send("mg retry/once v\r\n");
    $t->be_recv(0, "mg retry/once v\r\n", "attempt 1");
    $t->be_send(0, "EN\r\n");
    $t->c_recv("EN\r\n", "client got the first result");
    $t->clear();
};

subtest 'reset of an idle handle' => sub {
    $t->c_send("mg idle/a\r\n");
    $t->be_recv(0, "mg idle/a\r\n", "request sent");
    $t->be_send(0, "HD\r\n");
    $t->c_recv("HD\r\n");
    $t->clear();
};

subtest 'reset refused while in flight' => sub {
    $t->c_send("mg inflight/a\r\n");
    $t->be_recv(0, "mg inflight/a\r\n", "request sent");
    $t->c_recv("SERVER_ERROR reset false\r\n", "reset returned false");
    $t->be_send(0, "HD\r\n");
    $t->clear();
    is(active(), 0, "late response cleaned up");
};

subtest 'reset refused in a wait' => sub {
    $t->c_send("mg inwait/a\r\n");
    $t->be_recv(0, "mg inwait/a\r\n", "request sent");
    $t->be_send(0, "HD\r\n");
    $t->c_recv("SERVER_ERROR handle_reset: cannot reset handles while in a wait\r\n");
    $t->clear();
};

done_testing();

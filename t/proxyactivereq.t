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

my $t = Memcached::ProxyTest->new(servers => [12221]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyactivereq.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

sub count_is {
    my ($n, $detail) = @_;
    $t->c_send("mg count/x\r\n");
    $t->c_recv("SERVER_ERROR active $n\r\n", $detail);
}

# the request asking is active itself.
count_is(1, "only the current request");

$t->c_send("mg bg/a\r\n");
$t->c_recv("HD\r\n", "background request answered");
$t->be_recv(0, "mg bg/a\r\n", "backend received it");
count_is(2, "background request still counted");

$t->c_send("mg bg/b\r\n");
$t->c_recv("HD\r\n", "second background request answered");
$t->be_recv(0, "mg bg/b\r\n", "backend received it");
count_is(3, "both background requests counted");

$t->be_send(0, "HD\r\n");
$t->be_send(0, "HD\r\n");
# the responses are processed before the next client request is read.
my $tries = 0;
my $res;
while ($tries++ < 20) {
    print $ps "mg count/x\r\n";
    $res = <$ps>;
    last if $res eq "SERVER_ERROR active 1\r\n";
    select undef, undef, undef, 0.05;
}
is($res, "SERVER_ERROR active 1\r\n", "background requests done");
is(mem_stats($ps)->{proxy_req_active}, 0, "matches proxy_req_active");

done_testing();

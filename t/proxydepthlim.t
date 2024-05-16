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

my $t = Memcached::ProxyTest->new(servers => [12161]);

my $p_srv = new_memcached('-o proxy_config=./t/proxydepthlim.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
#$t->accept_backends();

subtest 'over-depth' => sub {
    my $holder = $p_srv->new_sock;
    # enqueue some requests.
    my $cmd = "mg foo s t v\r\n";
    my $todo = '';
    for (1..4) {
        $todo .= $cmd;
    }
    print $holder $todo;
    sleep 0.25; # ensure holder client is seen first
    diag "foo";
    # We never look at the backend in this test.
    $t->c_send($cmd);
    $t->c_recv("SERVER_ERROR backend failure\r\n", 'depth limit reached');

    my $s = mem_stats($ps);
    is($s->{proxy_request_failed_depth}, 1, "got a fast failure");
};

done_testing();

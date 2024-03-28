#!/usr/bin/env perl
# Check funcgen and memory accounting.

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

my $t = Memcached::ProxyTest->new(servers => [12131, 12132, 12133]);

my $p_srv = new_memcached('-o proxy_config=./t/proxybestats.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

subtest 'cause bad backends' => sub {
    my $s = mem_stats($ps, "proxybe");
    is(keys %$s, 0, "no bad backends");

    $t->close_backend(0);
    # wait for retry to mark it bad.
    sleep 1;
    $s = mem_stats($ps, "proxybe");
    is($s->{bad_b1}, 1, "b1 is now bad");

    # Could have multiple sockets queued as the proxy retries. We can get all
    # the way through read validation then not know if the socket was closed
    # until the _next_ time we read from it.
    # So we can either try to read and accept in a loop, or keep checking if
    # there's a conn waiting to be accepted.
    while ($t->srv_accept_waiting(0, 1)) {
        $t->accept_backend(0);
    }
    $s = mem_stats($ps, "proxybe");
    is(keys %$s, 0, "no bad backends anymore");

    $t->close_backend(1);
    $t->close_backend(2);
    sleep 1;
    $s = mem_stats($ps, "proxybe");
    is($s->{bad_b2}, 1, "b2 is now bad");
    is($s->{bad_b3}, 1, "b3 is now bad");
    for (1 .. 2) {
        while ($t->srv_accept_waiting($_, 1)) {
            $t->accept_backend($_);
        }
    }
    $s = mem_stats($ps, "proxybe");
    is(keys %$s, 0, "no bad backends anymore");

};

done_testing();

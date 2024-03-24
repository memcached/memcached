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

# Set up the listeners _before_ starting the proxy.
# the fourth listener is only occasionally used.
my $t = Memcached::ProxyTest->new(servers => [12111]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyconfigmulti1.lua:./t/proxyconfigmulti2.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

$t->c_send("mg foo\r\n");
$t->be_recv_c(0);
$t->be_send(0, "HD\r\n");
$t->c_recv_be();

done_testing();

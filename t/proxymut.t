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

my $t = Memcached::ProxyTest->new(servers => [12173]);

my $p_srv = new_memcached('-o proxy_config=./t/proxymut.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

my $w = $p_srv->new_sock;
print $w "watch proxyevents\r\n";
is(<$w>, "OK\r\n");

{
    test_mg();
}

sub test_mg {
    note 'test mut with initial mg commands';

    subtest 'mgreq' => sub {
        $t->c_send("mg mgreq\r\n");
        $t->be_recv(0, "mg override\r\n");
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'mgflagreq' => sub {
        $t->c_send("mg mgflagreq\r\n");
        $t->be_recv(0, "mg override s t Oopaque N33\r\n");
        $t->be_send(0, "HD s2 t33 Opaque\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'mgreqcopy' => sub {
        $t->c_send("mg mgreqcopy\r\n");
        $t->be_recv(0, "md differentkey\r\n");
        $t->be_send(0, "NF\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'mgres' => sub {
        $t->c_send("mg mgres\r\n");
        $t->c_recv("HD\r\n");
        # Do this twice in a row to be sure there isn't junk.
        $t->c_send("mg mgres\r\n");
        $t->c_recv("HD\r\n");
        $t->clear();
    };

    subtest 'mgresval' => sub {
        $t->c_send("mg mgresval\r\n");
        $t->c_recv("VA 13\r\n");
        $t->c_recv("example value\r\n");
        $t->clear();
    };

    subtest 'mgresflag' => sub {
        $t->c_send("mg mgresflag\r\n");
        $t->be_recv(0, "mg mgresflag\r\n");
        $t->be_send(0, "HD s2 Omgresflag f3\r\n");
        $t->c_recv("HD t37 Omgresflag\r\n");
        $t->clear();
    };

    subtest 'mgresflag2' => sub {
        $t->c_send("mg mgresflag2\r\n");
        $t->be_recv(0, "mg mgresflag2\r\n");
        $t->be_send(0, "HD s2 Omgresflag2 f3\r\n");
        $t->c_recv("HD t37 Otoast\r\n");
        $t->clear();
    };

    subtest 'mgreserr' => sub {
        $t->c_send("mg mgresteapot\r\n");
        $t->c_recv("SERVER_ERROR teapot\r\n");
        $t->clear();
    };
}

done_testing();

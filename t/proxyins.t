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

my $t = Memcached::ProxyTest->new(servers => [12172]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyins.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

my $w = $p_srv->new_sock;
print $w "watch proxyevents\r\n";
is(<$w>, "OK\r\n");

{
    test_mgintres();
    test_mgreq();
    test_mgres();
}

sub test_mgintres {
    note 'testing mcp.internal()';
    subtest 'mgintres 0b init' => sub {
        $t->c_send("ms intres/tokenint 0 F7\r\n");
        $t->c_send("\r\n");
        $t->c_recv("HD\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint 0b' => sub {
        $t->c_send("mg intres/tokenint f t s Omoo\r\n");
        $t->c_recv("SERVER_ERROR O[true]: moo t[true]: -1\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint with 0b value returned' => sub {
        $t->c_send("mg intres/tokenint v f t s Omoo\r\n");
        $t->c_recv("SERVER_ERROR O[true]: moo t[true]: -1\r\n");
        $t->clear();
    };

    subtest 'mgintres 5b init' => sub {
        $t->c_send("ms intres/tokenint 5 F5\r\n");
        $t->c_send("hello\r\n");
        $t->c_recv("HD\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint' => sub {
        $t->c_send("mg intres/tokenint f t s Omoo\r\n");
        $t->c_recv("SERVER_ERROR O[true]: moo t[true]: -1\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint with value returned' => sub {
        $t->c_send("mg intres/tokenint v f t s Omoo\r\n");
        $t->c_recv("SERVER_ERROR O[true]: moo t[true]: -1\r\n");
        $t->clear();
    };
}

sub test_mgreq {
    note 'test ins with mg req object';

    subtest 'sepkey with map' => sub {
        $t->c_send("mg sepkey/bar/restofkey s t v\r\n");
        $t->c_recv("SERVER_ERROR idx: 2 true\r\n");
        $t->clear();
    };

    subtest 'sepkey onesep' => sub {
        $t->c_send("mg sepkey/baz s t v\r\n");
        $t->c_recv("SERVER_ERROR idx: 1\r\n");
        $t->clear();
    };

    subtest 'sepkey nomap' => sub {
        $t->c_send("mg sepkey/nomap s t v\r\n");
        $t->c_recv("SERVER_ERROR str: nomap\r\n");
        $t->clear();
    };

    subtest 'sepkey one' => sub {
        $t->c_send("mg sepkey/one/two s t v\r\n");
        $t->c_recv("SERVER_ERROR idx: 3\r\n");
        $t->clear();
    };

    subtest 'sepkey three' => sub {
        $t->c_send("mg sepkey/two/three s t v\r\n");
        $t->c_recv("SERVER_ERROR idx: 3\r\n");
        $t->clear();
    };

    subtest 'keyis one' => sub {
        $t->c_send("mg reqkey/one s t v\r\n");
        $t->c_recv("SERVER_ERROR one[true] two[false] three[false]\r\n");
        $t->clear();
    };

    subtest 'keyis two' => sub {
        $t->c_send("mg reqkey/two s t v\r\n");
        $t->c_recv("SERVER_ERROR one[false] two[true] three[false]\r\n");
        $t->clear();
    };

    subtest 'keyis three' => sub {
        $t->c_send("mg reqkey/three s t v\r\n");
        $t->c_recv("SERVER_ERROR one[false] two[false] three[true]\r\n");
        $t->clear();
    };

    subtest 'keyis none' => sub {
        $t->c_send("mg reqkey/twoo s t v\r\n");
        $t->c_recv("SERVER_ERROR one[false] two[false] three[false]\r\n");
        $t->clear();
    };

}

sub test_mgres {
    note 'test ins with mg res object';

    subtest 'has flags' => sub {
        $t->c_send("mg reshasf/foo f t s\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD f1234 t9995\r\n");
        $t->c_recv("SERVER_ERROR f: true t: true\r\n");
        $t->clear();
    };

    subtest 'has flags with value returned' => sub {
        $t->c_send("mg reshasf/foo v f t s\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "VA 4 f1234 t9995\r\n");
        $t->be_send(0, "data\r\n");
        $t->c_recv("SERVER_ERROR f: true t: true\r\n");
        $t->clear();
    };

    subtest 'one flag' => sub {
        $t->c_send("mg reshasf/foo f t s\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD f1234 Oasdf\r\n");
        $t->c_recv("SERVER_ERROR f: true t: false\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint' => sub {
        $t->c_send("mg reshasf/tokenint f t s Omoo\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD f5678 t60 s300 Omoo\r\n");
        $t->c_recv("SERVER_ERROR O[true]: moo t[true]: 60\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint req' => sub {
        $t->c_send("mg reshasf/reqhasf Obar T333 s\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD Obar s300\r\n");
        $t->c_recv("SERVER_ERROR O[true]: bar T[true]: 333\r\n");
        $t->clear();
    };

    subtest 'flagtoken and flagint miss' => sub {
        $t->c_send("mg reshasf/tokenint f t s Omoo\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD f5678 s300\r\n");
        $t->c_recv("SERVER_ERROR O[false]: nil t[false]: nil\r\n");
        $t->clear();
    };

    subtest 'flagis' => sub {
        $t->c_send("mg reshasf/flagis Obaz\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD f Obaz\r\n");
        $t->c_recv("SERVER_ERROR exists[true] matches[true]\r\n");
        $t->clear();
    };

    subtest 'flagisnt' => sub {
        $t->c_send("mg reshasf/flagis Obar\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD f Obaz\r\n");
        $t->c_recv("SERVER_ERROR exists[true] matches[true]\r\n");
        $t->clear();
    };

}

done_testing();

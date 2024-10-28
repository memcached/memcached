#!/usr/bin/env perl
# tests specific to the proxy request object and meta protocol

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
my $t = Memcached::ProxyTest->new(servers => [12091]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyrequest.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

subtest 'req:flag_add()' => sub {
    $t->c_send("mg add1 N50\r\n");
    $t->be_recv(0, "mg add1 N50 F\r\n", "be received appended request");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg addstr N50\r\n");
    $t->be_recv(0, "mg addstr N50 F1234\r\n", "be received addstr request");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg addnum N50\r\n");
    $t->be_recv(0, "mg addnum N50 F5678\r\n", "be received addnum request");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg addexist Oexists\r\n");
    $t->c_recv("HD\r\n", "client didn't overwrite flag");
    $t->clear();
};

subtest 'req:flag_set()' => sub {
    $t->c_send("mg set1 N50\r\n");
    $t->be_recv(0, "mg set1 N50 F\r\n", "be received appended request");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg setstr N50\r\n");
    $t->be_recv(0, "mg setstr N50 F4321\r\n", "be received addstr request");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg setnum N50\r\n");
    $t->be_recv(0, "mg setnum N50 F8765\r\n", "be received addnum request");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg setexist N50 Oexists\r\n");
    $t->be_recv(0, "mg setexist N50 Ooverwrite\r\n", "O set at end");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg setexist N50 Oexists T73 c\r\n");
    $t->be_recv(0, "mg setexist N50 Ooverwrite T73 c\r\n", "O set in middle");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();

    $t->c_send("mg setflag N50 Oexists T73 c\r\n");
    $t->be_recv(0, "mg setflag N50 O T73 c\r\n", "O overwritten without token");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    $t->clear();
};

subtest 'req:flag_replace()' => sub {
    $t->c_send("mg repl1 N50 F1234 T73\r\n");
    $t->be_recv(0, "mg repl1 N50 Ofoo T73\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got repl1 test response');
    $t->clear();

    $t->c_send("mg repl2 N50 F5678 T73\r\n");
    $t->be_recv(0, "mg repl2 N50 O T73\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got repl2 test response');
    $t->clear();

    $t->c_send("mg repl1 F\r\n");
    $t->be_recv(0, "mg repl1 Ofoo\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got repl1 F response');
    $t->clear();
};

subtest 'req:flag_del()' => sub {
    $t->c_send("mg del1 N50 Oremove T80\r\n");
    $t->be_recv(0, "mg del1 N50 T80\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got del1 middle removal');
    $t->clear();

    $t->c_send("mg del1 N51 T81 Oremove\r\n");
    $t->be_recv(0, "mg del1 N51 T81\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got del1 end removal');
    $t->clear();

    $t->c_send("mg del1 Oremove N52 T82\r\n");
    $t->be_recv(0, "mg del1 N52 T82\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got del1 front removal');
    $t->clear();

    $t->c_send("mg del1 O N52 T82\r\n");
    $t->be_recv(0, "mg del1 N52 T82\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be('got del1 tokenless removal');
    $t->clear();
};

subtest 'req:flag_token_int()' => sub {
    $t->c_send("mg fint F59\r\n");
    $t->be_recv(0, "mg fint F591\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be("fint converted and adjusted");
    $t->clear();
};

subtest 'req:token_int()' => sub {
    $t->c_send("set setints 8 10 2\r\nhi\r\n");
    $t->be_recv(0, "set setints 20 10 2\r\n");
    $t->be_recv(0, "hi\r\n");
    $t->be_send(0, "STORED\r\n");
    $t->c_recv_be("setints fetched and modified data");
    $t->clear();
};

subtest 'mcp.request' => sub {
    # This test doesn't look at the request that was created inside lua, we
    # just ensure that it got through the loop without crashing.
    $t->c_send("mg toolong\r\n");
    $t->be_recv(0, "mg toolong\r\n");
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be("internally created long requests");
    $t->clear();
};

done_testing();

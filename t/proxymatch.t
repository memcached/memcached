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

my $t = Memcached::ProxyTest->new(servers => [12171]);

my $p_srv = new_memcached('-o proxy_config=./t/proxymatch.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

my $w = $p_srv->new_sock;
print $w "watch proxyuser proxyevents\n";
is(<$w>, "OK\r\n", "watcher enabled");

subtest 'ms no tokens' => sub {
    my $cmd = "ms foo 2\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

# successful tests.
subtest 'ms with k' => sub {
    my $cmd = "ms foo 2 k\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kfoo\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

subtest 'ms with O' => sub {
    my $cmd = "ms foo 2 k O1234\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kfoo O1234\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

subtest 'ms with k and O' => sub {
    my $cmd = "ms foo 2 k O4321\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kfoo O4321\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

subtest 'ms with O and k' => sub {
    my $cmd = "ms foo 2 O9876 k\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD O9876 kfoo\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

# ensure the parser works with unrelated tokens at the beginning/end of the string
subtest 'ms with O and k and c' => sub {
    my $cmd = "ms foo 2 T99 O9876 k c\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD O9876 kfoo c2\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

# test some failures.
subtest 'ms with empty k' => sub {
    my $cmd = "ms foo 2 k\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD k\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with empty O' => sub {
    my $cmd = "ms foo 2 O\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD O\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with empty O c' => sub {
    my $cmd = "ms foo 2 O c\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD O c2\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with wrong k' => sub {
    my $cmd = "ms foo 2 k\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kbar\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with wrong len k' => sub {
    my $cmd = "ms foo 2 k\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kfoob\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with wrong O' => sub {
    my $cmd = "ms foo 2 O1234\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD O4321\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with wrong len O' => sub {
    my $cmd = "ms foo 2 O1234\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD O43210\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with right k wrong O' => sub {
    my $cmd = "ms foo 2 k O1234\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kfoo O5678\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'ms with right O wrong k' => sub {
    my $cmd = "ms foo 2 k O1234\r\nok\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD kbar O1234\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

# don't need to test mg as hard since the match code is the same. just ensure
# the rline handling is correct for both code paths.

# mg successful tests
subtest 'mg with k' => sub {
    my $cmd = "mg foo t k\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD t99 kfoo\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

subtest 'mg with O' => sub {
    my $cmd = "mg foo t O1234\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD t99 O1234\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

subtest 'mg with O and k' => sub {
    my $cmd = "mg foo t O1234 k c\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD t98 O1234 kfoo c2\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match succeeded/);
    $t->clear();
};

# mg failures
subtest 'mg with wrong k' => sub {
    my $cmd = "mg foo t k\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD t97 kbar\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'mg with wrong O' => sub {
    my $cmd = "mg foo t O1234 c\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD t97 O4321 c2\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

subtest 'mg no matchable tokens' => sub {
    my $cmd = "mg foo t c\r\n";
    $t->c_send($cmd);
    $t->be_recv_c(0);
    $t->be_send(0, "HD t97 c2\r\n");
    $t->c_recv_be();
    like(<$w>, qr/match failed: /);
    $t->clear();
};

done_testing();

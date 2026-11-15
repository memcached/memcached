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

my $modefile = "/tmp/proxytagmode.lua";
my $t = Memcached::ProxyTest->new(servers => [12050]);

write_modefile('return "start"');
my $p_srv = new_memcached('-l 127.0.0.1:12051 -l tag_b_:127.0.0.1:12052 -l tag_cccc_:127.0.0.1:12053 -o proxy_config=./t/proxytags.lua -t 1', 12051);
my $ps = $p_srv->sock;
$ps->autoflush(1);

my $tagpsb = IO::Socket::INET->new(PeerAddr => "127.0.0.1:12052");
my $tagpsc = IO::Socket::INET->new(PeerAddr => "127.0.0.1:12053");

$t->set_c($ps);
$t->accept_backends();

{
    test_basic();
}

done_testing();

sub test_basic {
    subtest 'untagged pass-thru' => sub {
        $t->set_c($ps);
        $t->c_send("mg foo t\r\n");
        $t->be_recv_c(0, 'backend received pass-thru cmd');
        $t->be_send(0, "HD t97\r\n");
        $t->c_recv_be('client received pass-thru response');
    };

    subtest 'tag B works' => sub {
        $t->set_c($tagpsb);
        $t->c_send("mg bar t\r\n");
        # No backend, looking for string response.
        $t->c_recv("SERVER_ERROR tag B\r\n", 'received resp from tagged handler');
    };

    subtest 'tag CCCC works' => sub {
        $t->set_c($tagpsc);
        $t->c_send("mg baz t\r\n");
        # No backend, looking for string response.
        $t->c_recv("SERVER_ERROR tag CCCC\r\n", 'received resp from tagged handler');
    };
}

sub write_modefile {
    my $cmd = shift;
    open(my $fh, "> $modefile") or die "Couldn't overwrite $modefile: $!";
    print $fh $cmd;
    close($fh);
}

sub wait_reload {
    my $w = shift;
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
}

END {
    unlink $modefile;
}

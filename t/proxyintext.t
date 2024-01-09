#!/usr/bin/env perl
#
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

my $ext_path;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore.$$";

my $value;
{
    my @chars = ("C".."Z");
    for (1 .. 20000) {
        $value .= $chars[rand @chars];
    }
}

my $t = Memcached::ProxyTest->new(servers => [12081]);

my $p_srv = new_memcached("-m 64 -U 0 -o ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_item_size=512,ext_item_age=2,ext_path=$ext_path:64m,ext_max_sleep=100000,proxy_config=./t/proxyintext.lua -t 1");
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
#$t->accept_backends();

{
    test_basic();
    subtest 'extstore tests', \&test_ext;
}

done_testing();

sub test_basic {
    subtest 'top level in memory mcp.internal() values' => sub {
        $t->c_send("ms top/a 2 F1 Oa1\r\nhi\r\n");
        $t->c_recv("HD Oa1\r\n", "set small value");

        $t->c_send("mg top/a v f Oa2\r\n");
        $t->c_recv("VA 2 f1 Oa2\r\n", "header received");
        $t->c_recv("hi\r\n", "payload received");
        $t->clear();
    };

    subtest 'sub level in memory mcp.internal() values' => sub {
        plan skip_all => 'sub-rctx internal calls do not work';
        $t->c_send("ms split/b 2 F2 Ob1\r\nho\r\n");
        $t->c_recv("HD Ob1\r\n", "set small to subrctx");

        $t->c_send("mg split/b v f Ob2\r\n");
        $t->c_recv("VA 2 f2 Ob2\r\n", "header received");
        $t->c_recv("ho\r\n", "payload received");
        $t->clear();
    };
}

# don't need tons of keys for this test as we're focusing on fetch/return
# functionality.
sub test_ext {
    my $count = 20;
    for my $c (1 .. $count) {
        $t->c_send("ms top/$c 20000 F$c\r\n$value\r\n");
        $t->c_recv("HD\r\n");

        # sub-rctx internal calls do not work.
        #$t->c_send("ms split/$c 20000 F$c\r\n$value\r\n");
        #$t->c_recv("HD\r\n");
    }
    $t->clear();

    wait_ext_flush($ps);

    $t->c_send("mg top/1 f v\r\n");
    $t->c_recv("VA 20000 f1\r\n", "header received");
    $t->c_recv("$value\r\n", "value received");

    #$t->c_send("mg split/2 f v\r\n");
    #$t->c_recv("VA 20000 F2\r\n", "header received");
    #$t->c_recv("$value\r\n", "value received");
    $t->clear();
}

END {
    unlink $ext_path if $ext_path;
}

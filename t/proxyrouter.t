#!/usr/bin/env perl
# Was wondering why we didn't use subtest more.
# Turns out it's "relatively new", so it wasn't included in CentOS 5. which we
# had to support until a few years ago. So most of the tests had been written
# beforehand.

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
my $t = Memcached::ProxyTest->new(servers => [12021]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyrouter.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

{
    test_cmap();
    test_submap();
    test_basic();
    test_separators();
}

done_testing();

sub test_cmap {
    subtest 'check cmap only router' => sub {
        $t->c_send("gets one|test\r\n");
        $t->c_recv("SERVER_ERROR cmap_only gets\r\n");

        $t->c_send("gat 5 one|test\r\n");
        $t->c_recv("SERVER_ERROR cmap_only default\r\n");

        $t->clear();
    };
}

sub test_submap {
    subtest 'check sub map routing' => sub {
        $t->c_send("get cmd|test\r\n");
        $t->c_recv("SERVER_ERROR cmd_get\r\n", "routed to sub-mg function");

        $t->c_send("set cmd|test 0 0 2\r\nhi\r\n");
        $t->c_recv("SERVER_ERROR cmd_set\r\n", "routed to sub-ms function");

        $t->c_send("delete cmd|test\r\n");
        $t->c_recv("SERVER_ERROR default route\r\n", "routed to sub-ms function");

        $t->c_send("delete cmdd|test\r\n");
        $t->c_recv("SERVER_ERROR cmd_default\r\n", "fall all the way back to default route");

        $t->c_send("incr bar|foo 1\r\n");
        $t->c_recv("SERVER_ERROR cmap incr\r\n", "routed fallback to cmap");

        $t->c_send("decr bar|foo 1\r\n");
        $t->c_recv("SERVER_ERROR cmap decr\r\n", "routed fallback to cmap");

        $t->clear();
    };
}

sub test_basic {
    # If there's a lua stack leak somewhere running the query a few hundred
    # times will cause a crash.
    my $func_before = mem_stats($ps, "proxyfuncs");
    subtest 'loop checking for lua leak' => sub {
        for (1 .. 500) {
            $t->c_send("mg one|key t$_\r\n");
            $t->be_recv_c(0);
            $t->be_send(0, "EN\r\n");
            $t->c_recv_be();
        }
    };
    check_func_counts($ps, $func_before);
}

# Router has short and long prefix and anchored prefix modes
sub test_separators {
    subtest 'short separator' => sub {
        $t->c_send("mg one|key t3\r\n");
        $t->be_recv_c(0, 'backend received mg');
        $t->be_send(0, "EN\r\n");
        $t->c_recv_be();

        $t->c_send("mg one/found\r\n");
        $t->c_recv("SERVER_ERROR default route\r\n", 'got default route');
        $t->clear();
    };

    subtest 'long separator' => sub {
        $t->c_send("ms one+#+foo 2\r\nhi\r\n");
        $t->be_recv(0, "ms one+#+foo 2\r\n", 'backend received ms');
        $t->be_recv(0, "hi\r\n", 'backend received data');
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be();

        $t->c_send("ms one+#found 2\r\nhi\r\n");
        $t->c_recv("SERVER_ERROR default route\r\n", 'got default route');
        $t->clear();
    };

    subtest 'short anchor' => sub {
        $t->c_send("md _one,bar\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be();

        $t->c_send("md _one+nothing\r\n");
        $t->c_recv("SERVER_ERROR default route\r\n", 'got default route');
        $t->clear();
    };

    subtest 'long anchor' => sub {
        $t->c_send("ma =?=one__key\r\n");
        $t->be_recv_c(0, 'backend received ma');
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be();

        $t->c_send("ma =?=one_nothing\r\n");
        $t->c_recv("SERVER_ERROR default route\r\n", 'got default route');
        $t->clear();
    };
}

sub check_func_counts {
    my $c = shift;
    my $a = shift;
    my $b = mem_stats($c, "proxyfuncs");
    for my $key (keys %$a) {
        # Don't want to pollute/slow down the output with tons of ok's here,
        # so only fail on the fail conditions.
        if (! exists $b->{$key}) {
            fail("func stat gone missing: $key");
        }
        if ($a->{$key} != $b->{$key}) {
            cmp_ok($b->{$key}, '==', $a->{$key}, "func stat for $key");
        }
    }
}

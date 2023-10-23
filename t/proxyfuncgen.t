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
my $t = Memcached::ProxyTest->new(servers => [12011, 12012, 12013, 12014]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyfuncgen.lua');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

# Comment out unused sections when debugging.
test_basic();
test_waitfor();

done_testing();

sub test_waitfor {
    note 'stress testing rctx:wait_for scenarios';

    subtest 'wait_for(0)' => sub {
        $t->c_send("mg /waitfor/a\r\n");
        $t->c_recv("HD t1\r\n", 'client response before backends receive cmd');
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t9\r\n");
        $t->clear();
    };

    subtest 'wait_for(0) then wait_for(2)' => sub {
        $t->c_send("mg /waitfor/b t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t13\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'wait_for(0) then queue then wait_for(1)' => sub {
        $t->c_send("mg /waitfor/c t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t11\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'queue two, wait_handle individually' => sub {
        $t->c_send("mg /waitfor/d t\r\n");
        $t->be_recv_c([0, 1]);
        # respond from the non-waited be first
        $t->be_send(1, "HD t23\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(0, "HD t17\r\n");
        $t->c_recv("HD t23\r\n");
        $t->clear();
    };

    subtest 'failover route first success' => sub {
        $t->c_send("mg /failover/a t\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD t31\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'failover route failover success' => sub {
        $t->c_send("mg /failover/b t\r\n");
        $t->be_recv_c(0, 'first backend receives client req');
        $t->be_send(0, "EN\r\n");
        # TODO: test that they aren't active before we send the resposne to 0?
        $t->be_recv_c([1, 2], 'rest of be then receive the retry');
        $t->be_send(1, "EN\r\n");
        $t->be_send(2, "HD t41\r\n");
        $t->c_recv_be('client received last response');
    };

    subtest 'failover route failover fail' => sub {
        $t->c_send("mg /failover/c t\r\n");
        $t->be_recv_c(0, 'first backend receives client req');
        $t->be_send(0, "EN Ofirst\r\n");
        $t->be_recv_c([1, 2], 'rest of be receives retry');
        $t->be_send([1, 2], "EN Ofailover\r\n");
        $t->c_recv("EN Ofirst\r\n", 'client receives first res');
    };
}

sub test_basic {
    note 'basic functionality tests';

    subtest 'single backend route' => sub {
        $t->c_send("mg /single/a\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'first route' => sub {
        $t->c_send("mg /first/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        # respond from the other two backends first.
        $t->be_send([1, 2], "HD t5\r\n");
        $t->be_send(0, "HD t1\r\n");
        # receive just the last command.
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'partial route' => sub {
        $t->c_send("mg /partial/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send(0, "HD t4\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(1, "HD t4\r\n");
        $t->c_recv_be('response received after 2/3 returned');
        $t->be_send(2, "HD t5\r\n");
        $t->clear();
    };

    subtest 'all route' => sub {
        $t->c_send("mg /all/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1], "HD t1\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(2, "HD t1\r\n");
        $t->c_recv_be('response received after 3/3 returned');
        $t->clear();
    };

    subtest 'fastgood route' => sub {
        $t->c_send("mg /fastgood/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        # Send one valid but not a hit.
        $t->be_send(0, "EN\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(1, "HD t5\r\n");
        $t->c_recv_be('response received after first good');
        $t->be_send(2, "EN\r\n");
        $t->clear();
    };

    subtest 'blocker route' => sub {
        # The third backend is our blocker, first test that normal backends return
        # but we don't return to client.
        $t->c_send("mg /blocker/a t Ltest\r\n");
        $t->be_recv_c([0, 1, 2, 3]);
        $t->be_send([0, 1, 2], "HD t10\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(3, "HD t15\r\n");
        # Now, be sure we didn't receive the blocker response
        $t->c_recv("HD t10\r\n");
        $t->clear();

        note '... failed blocker';
        $t->c_send("mg /blocker/b t Ltest\r\n");
        $t->be_recv_c([0, 1, 2, 3]);
        $t->be_send([0, 1, 2], "HD t10\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(3, "EN\r\n");
        # Should get the blocker failed response.
        $t->c_recv("SERVER_ERROR blocked\r\n");
        $t->clear();
    };

    subtest 'logall route' => sub {
        my $w = $p_srv->new_sock;
        print $w "watch proxyuser\n";
        is(<$w>, "OK\r\n", 'watcher enabled');

        $t->c_send("mg /logall/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t3\r\n");
        $t->c_recv_be();
        for (0 .. 2) {
            like(<$w>, qr/received a response: /, 'got a log line');
        }
        $t->clear();
    };

    subtest 'summary_factory' => sub {
        my $w = $p_srv->new_sock;
        print $w "watch proxyuser\n";
        is(<$w>, "OK\r\n", 'watcher enabled');

        $t->c_send("mg /summary/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t8\r\n");
        $t->c_recv_be();
        like(<$w>, qr/received all responses/, 'got a log summary line');
        $t->clear();
    };
}


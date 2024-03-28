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

my $p_srv = new_memcached('-o proxy_config=./t/proxyfuncgen.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();
{
    # Comment out unused sections when debugging.
    test_pipeline();
    test_split();
    test_basic();
    test_waitfor();
    # Run test returns twice for extra leak checking.
    my $func_before = mem_stats($ps, "proxyfuncs");
    test_returns();
    test_returns();
    check_func_counts($ps, $func_before);
    test_errors();
}

done_testing();

# This kind of testing is difficult to do from integration level test suites
# like this, but do what we can.
sub test_errors {
    note 'test specific error handling';

    # Looking specifically for slot leaks. So we run the test N times and
    # check immediately.
    my $func_before = mem_stats($ps, "proxyfuncs");
    subtest 'bad data chunk' => sub {
        for (1 .. 3) {
            $t->c_send("ms badchunk 2\r\nfail");
            $t->c_recv("CLIENT_ERROR bad data chunk\r\n", "got bad data chunk response");
        }
        $t->clear();
    };
    check_func_counts($ps, $func_before);

    # Need to pipeline to force the second slot to generate.
    subtest 'slot generation failure' => sub {
        my $cmd = "md failgen/a\r\n";
        $t->c_send("$cmd$cmd");
        $t->c_recv("NF\r\n");
        $t->c_recv("SERVER_ERROR lua start failure\r\n");
        $t->clear();
    };

    subtest 'wrong return object' => sub {
        $t->c_send("mg badreturn/a\r\n");
        $t->c_recv("SERVER_ERROR bad response\r\n");
        $t->clear();
    };
}

sub test_pipeline {
    note 'test pipelining of requests';

    # We're expecting the slots to actually increase on the first loop, so
    # make sure we test that explicitly.
    my $func_before = mem_stats($ps, "proxyfuncs");

    subtest 'some pipelines' => sub {
        note 'run a couple pipelines to check for leaks';
        for my $count (1 .. 3) {
            my @keys = ("a".."f");
            my $cmd = '';
            for my $k (@keys) {
                $cmd .= "mg all/$k O$k\r\n";
            }
            $t->c_send("$cmd");
            for my $k (@keys) {
                $t->be_recv([0, 1, 2], "mg all/$k O$k\r\n", "backend received pipelined $k");
                $t->be_send([0, 1, 2], "HD O$k\r\n");
            }

            for my $k (@keys) {
                $t->c_recv("HD O$k\r\n", "client got res $k");
            }
            $t->clear();

            if ($count == 1) {
                my $func_after = mem_stats($ps, "proxyfuncs");
                cmp_ok($func_after->{"slots_all"}, '>=', $func_before->{"slots_all"}, 'slot count increased');
                # ensure we don't add more slots after this run.
                $func_before = $func_after;
            } else {
                check_func_counts($ps, $func_before);
            }
        }
    };

    subtest 'ensuring unique slot environments' => sub {
        # In each loop we send the command three times pipelined, but we
        # should get three unique lua environments.
        # In subsequent loops, the numbers will increment in lockstep.
        for my $x (1 .. 5) {
            # key doesn't matter; function isn't looking at it.
            my $cmd = "mg locality/a\r\n";
            $t->c_send("$cmd$cmd$cmd");
            for (1 .. 3) {
                $t->be_recv([0], $cmd, "backend 0 received locaity req");
                $t->be_send([0], "EN\r\n"); # not sending to client.
            }
            for (1 .. 3) {
                $t->c_recv("HD t$x\r\n", "client got return sequence $x");
            }
        }
    };
}

sub test_split {
    note 'test tiering of factories';

    my $func_before = mem_stats($ps, "proxyfuncs");
    # be's 0 and 3 are in use.
    subtest 'basic split' => sub {
        $t->c_send("mg split/a t\r\n");
        $t->be_recv_c([0, 3], 'each factory be gets the request');
        $t->be_send(3, "EN\r\n");
        $t->be_send(0, "HD t70\r\n");
        $t->c_recv_be('client received hit');
        $t->clear();
    };

    # one side of split is a complex function; doing its own waits and wakes.
    # other side is simple, and response ignored.
    subtest 'failover split' => sub {
        $t->c_send("mg splitfailover/f t\r\n");
        $t->be_recv_c(0, 'first backend receives client req');
        $t->be_recv_c(3, 'split factory gets client req');
        $t->be_send(3, "HD t133\r\n");

        # ensure all of the failover backends have their results processed.
        $t->be_send(0, "EN Ofirst\r\n");
        $t->be_recv_c([1, 2], 'rest of be receives retry');
        $t->be_send([1, 2], "EN Ofailover\r\n");
        $t->c_recv("EN Ofirst\r\n", 'client receives first res');
        $t->clear();
    };
    check_func_counts($ps, $func_before);
}

sub test_returns {
    note 'stress testing return scenarios for ctx and sub-ctx';

    # TODO: check that we don't re-generate a slot after each error type
    subtest 'top level result errors' => sub {
        $t->c_send("mg errors/reterror t\r\n");
        $t->c_recv("SERVER_ERROR lua failure\r\n", "lua threw an error");

        $t->c_send("mg errors/retnil t\r\n");
        $t->c_recv("SERVER_ERROR bad response\r\n", "lua returned nil");

        $t->c_send("mg errors/retint t\r\n");
        $t->c_recv("SERVER_ERROR bad response\r\n", "lua returned an integer");

        $t->c_send("mg errors/retnone t\r\n");
        $t->c_recv("SERVER_ERROR bad response\r\n", "lua returned nothing");
        $t->clear();
    };

    # TODO: method to differentiate a sub-rctx failure from a "backend
    # failure"
    subtest 'sub-rctx result errors' => sub {
        $t->c_send("mg suberrors/error t\r\n");
        $t->c_recv("SERVER_ERROR backend failure\r\n", "lua threw an error");

        $t->c_send("mg suberrors/nil t\r\n");
        $t->c_recv("SERVER_ERROR backend failure\r\n", "lua returned nil");

        $t->c_send("mg suberrors/int t\r\n");
        $t->c_recv("SERVER_ERROR backend failure\r\n", "lua returned an integer");

        $t->c_send("mg suberrors/none t\r\n");
        $t->c_recv("SERVER_ERROR backend failure\r\n", "lua returned nothing");
        $t->clear();
    };
}

sub test_waitfor {
    note 'stress testing rctx:wait_cond scenarios';

    my $func_before = mem_stats($ps, "proxyfuncs");
    subtest 'wait_fastgood: hit, c_recv, miss miss' => sub {
        $t->c_send("mg fastgoodint/a\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send(0, "HD t1\r\n");
        $t->c_recv_be('first good response');
        $t->be_send([1, 2], "EN Ohmm\r\n");
        $t->clear();
    };

    subtest 'wait_fastgood: miss, miss, c_recv, hit' => sub {
        $t->c_send("mg fastgoodint/a\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([1, 2], "EN Ommh\r\n");
        $t->c_recv_be('received miss');
        $t->be_send([0], "HD t40\r\n");
        $t->clear();
    };

    subtest 'wait_fastgood: miss, hit, hit' => sub {
        $t->c_send("mg fastgoodint/a\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send(0, "EN Omhh\r\n");
        $t->be_send(1, "HD t43\r\n");
        $t->be_send(2, "HD t44\r\n");
        $t->c_recv("HD t43\r\n", 'received first');
        $t->clear();
    };

    subtest 'wait_cond(0)' => sub {
        $t->c_send("mg waitfor/a\r\n");
        $t->c_recv("HD t1\r\n", 'client response before backends receive cmd');
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t9\r\n");
        $t->clear();
    };

    subtest 'wait_cond(0) then wait_cond(2)' => sub {
        $t->c_send("mg waitfor/b t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t13\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'wait_cond(0) then queue then wait_cond(1)' => sub {
        $t->c_send("mg waitfor/c t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t11\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'queue two, wait_handle individually' => sub {
        $t->c_send("mg waitfor/d t\r\n");
        $t->be_recv_c([0, 1]);
        # respond from the non-waited be first
        $t->be_send(1, "HD t23\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(0, "HD t17\r\n");
        $t->c_recv("HD t23\r\n");
        $t->clear();
    };

    # failover is referenced from another funcgen, so when we first fetch it
    # here we end up creating a new slot deliberately.
    $func_before->{slots_failover}++;
    subtest 'failover route first success' => sub {
        $t->c_send("mg failover/a t\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD t31\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'failover route failover success' => sub {
        $t->c_send("mg failover/b t\r\n");
        $t->be_recv_c(0, 'first backend receives client req');
        $t->be_send(0, "EN\r\n");
        # TODO: test that they aren't active before we send the resposne to 0?
        $t->be_recv_c([1, 2], 'rest of be then receive the retry');
        $t->be_send(1, "EN\r\n");
        $t->be_send(2, "HD t41\r\n");
        $t->c_recv_be('client received last response');
    };

    subtest 'failover route failover fail' => sub {
        $t->c_send("mg failover/c t\r\n");
        $t->be_recv_c(0, 'first backend receives client req');
        $t->be_send(0, "EN Ofirst\r\n");
        $t->be_recv_c([1, 2], 'rest of be receives retry');
        $t->be_send([1, 2], "EN Ofailover\r\n");
        $t->c_recv("EN Ofirst\r\n", 'client receives first res');
    };
    check_func_counts($ps, $func_before);
}

sub test_basic {
    note 'basic functionality tests';

    my $func_before = mem_stats($ps, "proxyfuncs");
    # actually referenced an extra time.
    $func_before->{slots_single}++;
    subtest 'single backend route' => sub {
        $t->c_send("mg single/a\r\n");
        $t->be_recv_c(0);
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'first route' => sub {
        $t->c_send("mg first/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        # respond from the other two backends first.
        $t->be_send([1, 2], "HD t5\r\n");
        $t->be_send(0, "HD t1\r\n");
        # receive just the last command.
        $t->c_recv_be();
        $t->clear();
    };

    subtest 'partial route' => sub {
        $t->c_send("mg partial/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send(0, "HD t4\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(1, "HD t4\r\n");
        $t->c_recv_be('response received after 2/3 returned');
        $t->be_send(2, "HD t5\r\n");
        $t->clear();
    };

    subtest 'all route' => sub {
        $t->c_send("mg all/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1], "HD t1\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(2, "HD t1\r\n");
        $t->c_recv_be('response received after 3/3 returned');
        $t->clear();
    };

    subtest 'fastgood route' => sub {
        $t->c_send("mg fastgood/a t\r\n");
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
        $t->c_send("mg blocker/a t Ltest\r\n");
        $t->be_recv_c([0, 1, 2, 3], 'received blocker requests');
        $t->be_send([0, 1, 2], "HD t10\r\n");
        ok(!$t->wait_c(0.2), 'client doesnt become readable');
        $t->be_send(3, "HD t15\r\n");
        # Now, be sure we didn't receive the blocker response
        $t->c_recv("HD t10\r\n");
        $t->clear();

        note '... failed blocker';
        $t->c_send("mg blocker/b t Ltest\r\n");
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
        print $w "watch proxyuser proxyreqs\n";
        is(<$w>, "OK\r\n", 'watcher enabled');

        $t->c_send("mg logall/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t3\r\n");
        $t->c_recv_be();
        for (0 .. 2) {
            like(<$w>, qr/received a response: /, 'got a log line');
            my $l2 = scalar <$w>;
            like($l2, qr/even more logs/, 'got logreq line');
            like($l2, qr/cfd=/, 'client file descriptor present');
            unlike($l2, qr/cfd=0/, 'client file descriptor is nonzero');
        }
        $t->clear();
    };

    subtest 'summary_factory' => sub {
        my $w = $p_srv->new_sock;
        print $w "watch proxyuser\n";
        is(<$w>, "OK\r\n", 'watcher enabled');

        $t->c_send("mg summary/a t\r\n");
        $t->be_recv_c([0, 1, 2]);
        $t->be_send([0, 1, 2], "HD t8\r\n");
        $t->c_recv_be();
        like(<$w>, qr/received all responses/, 'got a log summary line');
        $t->clear();
    };

    check_func_counts($ps, $func_before);
}

# To help debug, if a failure is encountered move this function up in its
# caller function and bisect.
# This is an out of band test: it won't fail on the test that breaks it.
# If a slot isn't returned properly the next test will generate one, and
# the counts will be off after that.
# This might mean to be absolutely sure, we should run the last test in a set
# twice.
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

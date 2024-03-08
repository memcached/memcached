#!/usr/bin/env perl
# Check funcgen and memory accounting.

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

# Set up the listeners _before_ starting the proxy.
# the fourth listener is only occasionally used.
my $t = Memcached::ProxyTest->new(servers => [12101]);

my $p_srv = new_memcached('-o proxy_config=./t/proxyslotcache.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

sub get_mem {
    $t->c_send("mg one/collect\r\n");
    # TODO: func to just read the client data back out?
    my $mem = scalar <$ps>;
    like($mem, qr/^SERVER_ERROR \d+/, "got garbage size back");
    # get the beginning total memory usage
    $mem =~ s/^SERVER_ERROR (\d+).+$/$1/s;

    return $mem;
}

sub slot_test {
    my $prefix = shift;
    my $etotal = shift; # expected slot total

    my $mem_start = get_mem();
    my $cmd = "mg $prefix/go N50\r\n";
    my $fcmd = '';
    my $cnt = 100;
    for (1 .. $cnt) {
        $fcmd .= $cmd;
    }
    $t->c_send($fcmd);
    # first receive all requests but don't send responses to ensure all
    # coroutines are generated.
    for (1 .. $cnt) {
        $t->be_recv(0, $cmd, "received request $_");
    }
    ok("received all requests");
    for (1 .. $cnt) {
        $t->be_send(0, "HD\r\n");
    }
    # once all responses are received the client gets woken up again.
    for (1 .. $cnt) {
        $t->c_recv_be("received response $_");
    }
    $t->clear();

    my $stats = mem_stats($ps, "proxyfuncs");
    is($stats->{funcs_foo}, 6, "six total function");
    is($stats->{slots_foo}, $etotal, "$etotal total slots in use");
    my $mem_middle = get_mem();
    cmp_ok($mem_start * 1.5, '<', $mem_middle, "memory usage grew a bit: $mem_start - $mem_middle");

    # run some non-pipelined requests and check that slots are still max
    for (1 .. 50) {
        $t->c_send("mg $prefix/go C$_\r\n");
        $t->be_recv_c(0, "received request $_");
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be("received response $_");
    }

    $stats = mem_stats($ps, "proxyfuncs");
    is($stats->{funcs_foo}, 6, "after batch: six total function");
    is($stats->{slots_foo}, $etotal, "after batch: $etotal total slots in use");

    # run some more and check that slots have dropped
    for (1 .. 100) {
        $t->c_send("mg $prefix/go C$_\r\n");
        $t->be_recv_c(0, "received request $_");
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be("received response $_");
    }

    $stats = mem_stats($ps, "proxyfuncs");
    is($stats->{funcs_foo}, 6, "after batch 2: six total function");
    cmp_ok($stats->{slots_foo}, '<', $etotal, "after batch 2: fewer total slots in use");
    cmp_ok($stats->{slots_foo}, '>', 1, "after batch 2: ... but more than one slot");

    # run enough to drop below 1 and check that it's 1
    for (1 .. (12 * $cnt)) {
        $t->c_send("mg $prefix/go C$_\r\n");
        $t->be_recv_c(0, "received request $_");
        $t->be_send(0, "HD\r\n");
        $t->c_recv_be("received response $_");
    }

    $stats = mem_stats($ps, "proxyfuncs");
    is($stats->{funcs_foo}, 6, "final batch: six total function");
    # algorithm will reduce slot cache count down to 2, not one. so we have
    # one more slot than functions.
    is($stats->{slots_foo}, 6, "final batch: 6 slots");
    my $mem_end = get_mem();
    cmp_ok($mem_start * 1.5, '>', $mem_end, "memory usage dropped back: $mem_start - $mem_end");

}

# minimum slot count is 6.
# "two" is two total slots per top level slot.
# "three" is three total slots per top level slot"
# so "three" * 100 + 3 extra base slots from two and one being unused
# ... is where that weird 303 comes from.
subtest 'excess slot freeing depth 1' => sub {
    slot_test("one", 105);
};

subtest 'excess slot freeing depth 2' => sub {
    slot_test("two", 204);
};

subtest 'excess slot freeing depth 3' => sub {
    slot_test("three", 303);
};

sub wait_reload {
    my $w = shift;
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
}

# reload a bunch of times and check that the proxyfuncs slots aren't
# leaking and the total memory usage isn't consistently creeping up
subtest 'reload memory leaks' => sub {
    my $mem_start = get_mem();
    my $watcher = $p_srv->new_sock;
    print $watcher "watch proxyevents\n";
    is(<$watcher>, "OK\r\n", "watcher enabled");

    my $mem_end = 0;
    my $mem_end_last = 0;
    for (1 .. 20) {
        my $cmd = "mg three/go N50\r\n";
        my $fcmd = '';
        my $cnt = 100;
        for (1 .. $cnt) {
            $fcmd .= $cmd;
        }
        $t->c_send($fcmd);
        for (1 .. $cnt) {
            $t->be_recv(0, $cmd, "received request $_");
            $t->be_send(0, "HD\r\n");
        }
        for (1 .. $cnt) {
            $t->c_recv_be("received response $_");
        }

        $p_srv->reload();
        wait_reload($watcher);
        # start tracking end memory after looping once.
        my $mem_end = get_mem();
        if ($mem_end_last) {
            is($mem_end, $mem_end_last, "post-collect $_: $mem_end is the same");
        }
        $mem_end_last = $mem_end;
    }

    $mem_end = get_mem();

    cmp_ok($mem_end, '<', $mem_start * 2, "memory didn't bloat");
    my $stats = mem_stats($ps, "proxyfuncs");
    is($stats->{funcs_foo}, 6, "post reload: function count");
    is($stats->{slots_foo}, 6, "post reload: slot count matches func count");
};

done_testing();

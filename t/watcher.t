#!/usr/bin/perl
# Networked logging tests.

use strict;
use warnings;
use Socket qw/SO_RCVBUF/;

use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 60 -o watcher_logbuf_size=8');
my $client = $server->sock;
my $watcher = $server->new_sock;

# This doesn't return anything.
print $watcher "watch\n";
my $res = <$watcher>;
is($res, "OK\r\n", "watcher enabled");

print $client "get foo\n";
$res = <$client>;
is($res, "END\r\n", "basic get works");
my $spacer = "X"x180;

# This is a flaky test... depends on buffer sizes. Could either have memc
# shrink the watcher buffer, or loop this and keep doubling until we get some
# skipped values.
for (1 .. 80000) {
    print $client "get foo$_$spacer\n";
    $res = <$client>;
}

# Let the logger thread catch up before we start reading.
sleep 1;
my $do_fetch = 0;
#print STDERR "RESULT: $res\n";
while (my $log = <$watcher>) {
    # The "skipped" line won't actually print until some space frees up in the
    # buffer, so we need to occasionally cause new lines to generate.
    if (($do_fetch++ % 100) == 0) {
         print $client "get foo\n";
         $res = <$client>;
    }
    next unless $log =~ m/skipped/;
    like($log, qr/skipped=/, "skipped some lines");
    # This should unjam more of the text.
    print $client "get foob\n";
    $res = <$client>;
    last;
}
$res = <$watcher>;
like($res, qr/ts=\d+\.\d+\ gid=\d+ type=item_get/, "saw a real log line after a skip");

# test combined logs
# fill to evictions, then enable watcher, set again, and look for both lines

{
    my $value = "B"x11000;
    my $keycount = 8000;

    for (1 .. $keycount) {
        print $client "set n,foo$_ 0 0 11000 noreply\r\n$value\r\n";
    }

    $watcher = $server->new_sock;
    print $watcher "watch mutations evictions\n";
    $res = <$watcher>;
    is($res, "OK\r\n", "new watcher enabled");
    my $watcher2 = $server->new_sock;
    print $watcher2 "watch evictions\n";
    $res = <$watcher2>;
    is($res, "OK\r\n", "evictions watcher enabled");

    print $client "set bfoo 0 0 11000 noreply\r\n$value\r\n";
    my $found_log = 0;
    my $found_ev  = 0;
    while (my $log = <$watcher>) {
        $found_log = 1 if ($log =~ m/type=item_store/);
        $found_ev = 1 if ($log =~ m/type=eviction/);
        last if ($found_log && $found_ev);
    }
    is($found_log, 1, "found rawcmd log entry");
    is($found_ev, 1, "found eviction log entry");
}

#!/usr/bin/perl
# Networked logging tests.

use strict;
use warnings;
use Socket qw/SO_RCVBUF/;

use Test::More tests => 12;
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

# testing the longest uri encoded key length
{
my $new_watcher = $server->new_sock;
print $new_watcher "watch mutations\n";
my $watch_res = <$new_watcher>;
my $key = "";
my $max_keylen = 250;
for (1 .. $max_keylen) { $key .= "#"; }
print $client "set $key 0 0 9\r\nmemcached\r\n";
$res = <$client>;
is ($res, "STORED\r\n", "stored the long key");
if ($res eq "STORED\r\n") {
    $watch_res = <$new_watcher>;
    my $max_uri_keylen = $max_keylen * 3 + length("key=");
    my @tab = split(/\s+/, $watch_res);
    is (length($tab[3]), $max_uri_keylen, "got the correct uri encoded key length");;
}
}

# test combined logs
# fill to evictions, then enable watcher, set again, and look for both lines

{
    my $value = "B"x11000;
    my $keycount = 8000;

    for (1 .. $keycount) {
        print $client "set n,foo$_ 0 0 11000 noreply\r\n$value\r\n";
    }
    # wait for all of the writes to go through.
    print $client "version\r\n";
    $res = <$client>;

    my $mwatcher = $server->new_sock;
    print $mwatcher "watch mutations evictions\n";
    $res = <$mwatcher>;
    is($res, "OK\r\n", "new watcher enabled");
    my $watcher2 = $server->new_sock;
    print $watcher2 "watch evictions\n";
    $res = <$watcher2>;
    is($res, "OK\r\n", "evictions watcher enabled");

    print $client "set bfoo 0 0 11000 noreply\r\n$value\r\n";
    my $found_log = 0;
    my $found_ev  = 0;
    while (my $log = <$mwatcher>) {
        $found_log = 1 if ($log =~ m/type=item_store/);
        $found_ev = 1 if ($log =~ m/type=eviction/);
        last if ($found_log && $found_ev);
    }
    is($found_log, 1, "found rawcmd log entry");
    is($found_ev, 1, "found eviction log entry");
}

# test cas command logs
# TODO: need to expose active watchers in stats, so we can monitor for when
# the previous ones are fully disconnected. They might be swallowing the logs
# before we get them. Since I can't reproduce this locally and travis takes 30
# minutes to fail I can't instrument this.
SKIP: {
    skip "Mysteriously fails on travis CI.", 1;
    $watcher = $server->new_sock;
    print $watcher "watch mutations\n";
    $res = <$watcher>;
    is($res, "OK\r\n", "mutations watcher enabled");

    # There's a bit of a startup race where some workers may not have the log
    # enabled yet, so we try a little harder to get the log line in there.
    sleep 1;
    for (1 .. 20) {
        print $client "cas cas_watch_key 0 0 5 0\r\nvalue\r\n";
        $res = <$client>;
    }
    my $tries = 30;
    my $found_cas = 0;
    while (my $log = <$watcher>) {
        $found_cas = 1 if ($log =~ m/cmd=cas/ && $log =~ m/cas_watch_key/);
        last if ($tries-- == 0 || $found_cas);
    }
    is($found_cas, 1, "correctly logged cas command");
}

# test no_watch option
{
    my $nowatch_server = new_memcached('-W');
    my $watchsock = $nowatch_server->new_sock;

    print $watchsock "watch mutations\n";

    my $watchresult = <$watchsock>;

    is($watchresult, "CLIENT_ERROR watch commands not allowed\r\n", "attempted watch gave client error with no_watch option set");
}

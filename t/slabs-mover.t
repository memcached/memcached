#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

# Enable manual slab reassign, cap at 6 slabs
# Items above 16kb are chunked
# disable LRU crawler so we can be sure to move expired items
my $server = new_memcached('-o no_lru_crawler,slab_reassign,slab_automove=0,slab_chunk_max=16 -m 12');
my $sock = $server->sock;

{
    subtest 'syntax' => \&test_syntax;
    subtest 'fill and move pages' => \&test_fill;
    subtest 'chunked items' => \&test_chunked;
    subtest 'test locked' => \&test_locked;
    subtest 'expired items' => \&test_expired;
    # Need clean memory for the reflock tests
    print $sock "flush_all\r\n";
    is(scalar <$sock>, "OK\r\n", "flushed items before reflock test");
    subtest 'reflocked items' => \&test_reflocked;
    # test reflocked chunked items (ensure busy_deletes)
}

sub wait_for_stat_incr {
    my $stats = shift;
    my $stat = shift;
    my $amt = shift; # 0 is valid

    my $stats_a;
    my $to_sleep = 0.01;
    for my $cnt (1 .. 500) {
        $stats_a = mem_stats($sock);
        last if ($stats_a->{$stat} > $stats->{$stat}+$amt);
        sleep $to_sleep;
        $to_sleep += $cnt / 100;
        #print STDERR Dumper(map { $_ => $stats_a->{$_} } sort keys %$stats_a), "\n";
    }
    return $stats_a;
}

sub find_largest_clsid {
    my $s = mem_stats($sock, 'slabs');
    my $sid = 0;
    my $total_pages = 0;
    # Find the highest ID to source from.
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+):total_pages/;
        if ($s->{$k} > $total_pages) {
            $sid = $1;
            $total_pages = $s->{$k};
        }
    }
    return $sid;
}

# NOTE: Can't validate reflocked items in an integration test since we leak
# the memory and cannot de-ref an unlinked item.
# TODO: test reflocked chunked items as well
sub test_reflocked {
    my $size = 9000;
    my $bigdata = 'x' x $size;
    my $stats;
    my $count = 1;
    $stats = mem_stats($sock);
    for my $c (1 .. 10000) {
        my $exp = $c % 2 == 1 ? "T0" : "T30";
        print $sock "ms rfoo$c $size $exp\r\n", $bigdata, "\r\n";
        is(scalar <$sock>, "HD\r\n", "stored big key: $c [$exp]");
        my $s_after = mem_stats($sock);
        last if ($s_after->{evictions} > $stats->{evictions});
        $count++;
    }

    # delete one page worth so we have memory to work with to move pages
    # non-destructively.
    my $todelete = int((1024 * 1024) / $size)+1;
    for (0 .. $todelete) {
        # delete from the newest since we move the oldest page.
        # encourages chunk rescues.
        my $i = $count - $_;
        print $sock "delete rfoo$i\r\n";
        is(scalar <$sock>, "DELETED\r\n", "deleted rfoo$i");
    }

    # attempt to reflock a bunch so we hit both expired and active rescue
    for (2 .. $count - ($todelete+1)) {
        print $sock "debugitem ref rfoo$_\r\n";
        is(scalar <$sock>, "OK\r\n", "reflocked rfoo$_");
    }

    mem_move_time($sock, 60);

    my $sid = find_largest_clsid($sock);

    $stats = mem_stats($sock);
    print $sock "slabs reassign $sid 0\r\n";
    is(scalar <$sock>, "OK\r\n", "reassign started");
    my $stats_a = wait_for_stat_incr($stats, "slab_reassign_busy_items", 500);

    cmp_ok($stats_a->{slab_reassign_busy_items}, '>', $stats->{slab_reassign_busy_items}+500, "page mover busy");
    # TODO: rescue counter is only updated after a page completes moving.
    #cmp_ok($stats_a->{slab_reassign_rescues}, '>', $stats->{slab_reassign_rescues}+50, "page mover rescued data");
    cmp_ok($stats_a->{slabs_moved}, '==', $stats->{slabs_moved}, "no page moved");

}

# TODO: reflock some items so we hit the "expired but reflocked" path
# TODO: use debugtime to move clock and avoid having to sleep.
# - also so we can reflock some items without having a race condition by
# setting the expire time out a minute/hour.
sub test_expired {
    my $size = 9000;
    my $bigdata = 'x' x $size;
    my $stats;
    my $count = 1;
    $stats = mem_stats($sock);
    for my $c (1 .. 10000) {
        my $exp = $c % 2 == 1 ? "T0" : "T30";
        print $sock "ms efoo$c $size $exp\r\n", $bigdata, "\r\n";
        is(scalar <$sock>, "HD\r\n", "stored big key");
        my $s_after = mem_stats($sock);
        last if ($s_after->{evictions} > $stats->{evictions});
        $count++;
    }

    mem_move_time($sock, 60);

    my $sid = find_largest_clsid($sock);

    $stats = mem_stats($sock);
    empty_class(mem_stats($sock), $sid);

    my $stats_a = mem_stats($sock);
    # TODO: there's no counter for "expired items reaped"
    # if we get here we at least didn't crash though.
}

# use debugitem command to deliberately hang the page mover
# NOTE: test is slightly flaky since we have to pick an item to lock that's in
# the page we want to move. this won't normally change but could if you
# re-order the tests.
sub test_locked {
    my $size = 9000;
    my $bigdata = 'x' x $size;
    my $stats;
    my $count = 1;
    $stats = mem_stats($sock);
    for (1 .. 10000) {
        print $sock "set lfoo$_ 0 0 $size\r\n", $bigdata, "\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored big key");
        my $s_after = mem_stats($sock);
        last if ($s_after->{evictions} > $stats->{evictions});
        $count++;
    }

    my $s = mem_stats($sock, 'slabs');
    my $sid = 0;
    my $total_pages = 0;
    # Find the highest ID to source from.
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+):total_pages/;
        if ($s->{$k} > $total_pages) {
            $sid = $1;
            $total_pages = $s->{$k};
        }
    }

    print $sock "debugitem lock lfoo50\r\n";
    is(scalar <$sock>, "OK\r\n", "locked item");

    $stats = mem_stats($sock);
    print $sock "slabs reassign $sid 0\r\n";
    is(scalar <$sock>, "OK\r\n", "reassign started");
    my $stats_a = wait_for_stat_incr($stats, "slab_reassign_busy_items", 500);

    cmp_ok($stats_a->{slab_reassign_busy_items}, '>', $stats->{slab_reassign_busy_items}+500, "page mover busy");
    cmp_ok($stats_a->{slabs_moved}, '==', $stats->{slabs_moved}, "no page moved");
    is($stats_a->{slab_reassign_running}, 1, "reassign stuck running");

    print $sock "debugitem unlock lfoo50\r\n";
    is(scalar <$sock>, "OK\r\n", "unlocked item");

    $stats_a = wait_for_stat_incr($stats, "slabs_moved", 0);
    cmp_ok($stats_a->{slabs_moved}, '>', $stats->{slabs_moved}, "page moved");
    is($stats_a->{slab_reassign_running}, 0, "reassign stopped running");

    empty_class(mem_stats($sock), $sid);
    $stats = mem_stats($sock);
    cmp_ok($stats->{slab_global_page_pool}, '>', 5, "pages back in global pool");
}

sub test_chunked {
    # Patterned value so we can tell if chunks get corrupted
    my $value;
    my $size = 30000;
    {
        my @chars = ("C".."Z");
        for (1 .. $size) {
            $value .= $chars[rand @chars];
        }
    }

    my $stats = mem_stats($sock);

    my $count = 1;
    while (1) {
        print $sock "set cfoo$count 0 0 $size\r\n$value\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored chunked item");
        my $s_after = mem_stats($sock);
        last if ($s_after->{evictions} > $stats->{evictions});
        $count++;
    }

    # hold stats to compare evictions later
    $stats = mem_stats($sock);
    my $s = mem_stats($sock, 'slabs');
    my $sid = 0;
    # Find the highest ID to source from.
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+):/;
        $sid = $1 if $1 > $sid;
    }

    cmp_ok($s->{"$sid:total_pages"}, '>', 5, "most pages in high class");
    cmp_ok($s->{"$sid:used_chunks"}, '>', 500, "many chunks in use");

    # move one page while full to force evictions
    print $sock "slabs reassign $sid 0\r\n";
    my $stats_a = wait_for_stat_incr($stats, "slabs_moved", 0);
    cmp_ok($stats_a->{evictions}, '>', $stats->{evictions}, "page move caused some evictions: " . ($stats_a->{evictions} - $stats->{evictions}));

    # delete at least a page worth so we can test rescuing data
    $s = mem_stats($sock, 'slabs');
    cmp_ok($s->{"$sid:free_chunks"}, '<', 5, "few free chunks available to start");
    cmp_ok($stats->{slab_reassign_chunk_rescues}, '<', 1, 'few chunk rescues happened');
    my $todelete = int((1024 * 1024) / $size)+1;
    for (0 .. $todelete) {
        # delete from the newest since we move the oldest page.
        # encourages chunk rescues.
        my $i = $count - $_;
        print $sock "delete cfoo$i\r\n";
        is(scalar <$sock>, "DELETED\r\n", "deleted cfoo$i");
    }

    $stats = mem_stats($sock);
    print $sock "slabs reassign $sid 0\r\n";
    $stats_a = wait_for_stat_incr($stats, "slabs_moved", 0);

    cmp_ok($stats_a->{slab_reassign_chunk_rescues}, '>', 50, 'more chunk rescues happened');
    cmp_ok($stats_a->{slab_reassign_busy_deletes}, '==', $stats->{slab_reassign_busy_deletes}, 'no busy deletes');

    # TODO: fetch all items back and check value

    empty_class(mem_stats($sock), $sid);
    $stats = mem_stats($sock);
    cmp_ok($stats->{slab_global_page_pool}, '>', 6, "pages back in global pool");
}

# Fill test, no chunked items.
sub test_fill {
    my $size = 15000;
    my $bigdata = 'x' x $size;
    my $stats;
    for (1 .. 10000) {
        print $sock "set bfoo$_ 0 0 $size\r\n", $bigdata, "\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored big key");
        $stats = mem_stats($sock);
        last if ($stats->{evictions} != 0);
    }

    # fill a smaller slab too
    $size = 2000;
    my $smalldata = 'y' x $size;
    for (1 .. 10000) {
        print $sock "set sfoo$_ 0 0 $size\r\n", $smalldata, "\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored small key");
        my $nstats = mem_stats($sock);
        last if ($stats->{evictions} < $nstats->{evictions});
    }

    my $slabs_before = mem_stats($sock, "slabs");
    #print STDERR Dumper($slabs_before), "\n\n";
    # Find our two slab classes.
    # low, high
    my @classes = sort map { /(\d+):/ } grep {/total_pages/} keys %$slabs_before;
    is(scalar @classes, 2, "right number of active classes");
    my $cls_small = $classes[0];
    my $cls_big = $classes[1];

    $stats = mem_stats($sock);
    is($stats->{slabs_moved}, 0, "no slabs moved before testing");
    is($stats->{evictions}, 2, "only two total evictions before testing");
    print $sock "slabs reassign $cls_big $cls_small\r\n";
    is(scalar <$sock>, "OK\r\n", "slab rebalancer started: $cls_big -> $cls_small");

    $stats = wait_for_stat_incr($stats, "slabs_moved", 0);

    isnt($stats->{slabs_moved}, 0, "slab moved within time limit");
    my $slabs_after = mem_stats($sock, "slabs");
    isnt($slabs_before->{"$cls_small:total_pages"}, $slabs_after->{"$cls_small:total_pages"},
        "slab $cls_small pagecount changed");
    isnt($slabs_before->{"$cls_big:total_pages"}, $slabs_after->{"$cls_big:total_pages"},
        "slab $cls_big pagecount changed");
    cmp_ok($stats->{slab_reassign_busy_nomem}, '>', 1, 'busy looped due to lack of memory');
    cmp_ok($stats->{evictions}, '>', 10, 'ran normal evictions to move page');
    # inline reclaim and other stats might be nonzero: evicted, then tried to
    # allocate memory and it was from the page we intended to move.
    # not intentionally causing that here.

    # Move another page
    my $stats_after;
    print $sock "slabs reassign $cls_big $cls_small\r\n";
    is(scalar <$sock>, "OK\r\n", "slab rebalancer started: $cls_big -> $cls_small");

    $stats_after = wait_for_stat_incr($stats, "slabs_moved", 0);

    cmp_ok($stats_after->{slabs_moved}, '>', $stats->{slabs_moved}, 'moved another page');

    # move all possible pages back to global
    empty_class(mem_stats($sock), $cls_big);
    empty_class(mem_stats($sock), $cls_small);
    $stats = mem_stats($sock);
    is($stats->{slab_global_page_pool}, 10, "pages back in global pool");

    #print STDERR Dumper(map { $_ => $stats->{$_} } sort keys %$stats), "\n";
}

sub empty_class {
    my $stats = shift;
    my $cls = shift;
    my $stats_after = $stats;
    while (1) {
        $stats = $stats_after;
        print $sock "slabs reassign $cls 0\r\n";
        my $res = <$sock>;
        if ($res =~ m/NOSPARE/) {
            pass("NOSPARE received while moving pages");
            last;
        }
        is($res, "OK\r\n", "slab rebalancer started: $cls -> 0");
        $stats_after = wait_for_stat_incr($stats, "slabs_moved", 0);
    }
}

sub test_syntax {
    my $stats = mem_stats($sock, ' settings');
    is($stats->{slab_reassign}, "yes");

    print $sock "slabs reassign invalid1 invalid2\r\n";
    is(scalar <$sock>, "CLIENT_ERROR bad command line format\r\n");

    print $sock "slabs reassign 5\r\n";
    is(scalar <$sock>, "ERROR\r\n");

    print $sock "slabs reassign 1 1\r\n";
    is(scalar <$sock>, "SAME src and dst class are identical\r\n");

    print $sock "slabs reassign -5 70\r\n";
    is(scalar <$sock>, "BADCLASS invalid src or dst class id\r\n");

    print $sock "slabs reassign 2 1\r\n";
    is(scalar <$sock>, "NOSPARE source class has no spare pages\r\n");
}

done_testing();

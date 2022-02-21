#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

my $ext_path;
my $ext_path2;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore1.$$";
$ext_path2 = "/tmp/extstore2.$$";

my $server = new_memcached("-m 256 -U 0 -o ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path:64m:default,ext_path=$ext_path2:96m:compact,slab_automove=1,ext_max_sleep=100000");
my $sock = $server->sock;

my $value;
my $lvalue;
{
    my @chars = ("C".."Z");
    for (1 .. 20000) {
        $value .= $chars[rand @chars];
    }
    for (1 .. 15000) {
        $lvalue .= $chars[rand @chars];
    }
}

# fill some larger objects
{
    my $free_before = summarize_buckets(mem_stats($sock, ' extstore'));
    my $keycount = 1200;
    for (1 .. $keycount) {
        print $sock "set nfoo$_ 0 0 20000 noreply\r\n$value\r\n";
        print $sock "set lfoo$_ 0 0 20000 noreply\r\n$value\r\n";
    }
    # wait for a flush
    wait_ext_flush($sock);
    # delete half
    mem_get_is($sock, "nfoo1", $value);
    for (1 .. $keycount) {
        print $sock "delete lfoo$_ noreply\r\n";
    }
    #    print $sock "lru_crawler crawl all\r\n";
    #<$sock>;
    # set a few more to kick off compaction?
    $keycount = 2000;
    for (1 .. $keycount) {
        print $sock "set kfoo$_ 0 0 15000 noreply\r\n$lvalue\r\n";
    }
    # wait for a flush
    wait_ext_flush($sock);

    # check extstore counters
    my $free_after = summarize_buckets(mem_stats($sock, ' extstore'));
    my $stats = mem_stats($sock);
    is($stats->{evictions}, 0, 'no RAM evictions');
    cmp_ok($stats->{extstore_page_allocs}, '>', 0, 'at least one page allocated');
    cmp_ok($stats->{extstore_objects_written}, '>', $keycount / 2, 'some objects written');
    cmp_ok($stats->{extstore_bytes_written}, '>', length($value) * 2, 'some bytes written');
    cmp_ok($stats->{get_extstore}, '>', 0, 'one object was fetched');
    cmp_ok($stats->{extstore_objects_read}, '>', 0, 'one object read');
    cmp_ok($stats->{extstore_bytes_read}, '>', length($value), 'some bytes read');
    cmp_ok($stats->{extstore_page_reclaims}, '>', 1, 'at least two pages reclaimed');
    cmp_ok($stats->{extstore_compact_rescues}, '>', 1, 'at least two compact rescues');
    cmp_ok($free_before->[1], '>', 0, 'compact bucket has dedicated free pages');
    cmp_ok($free_before->[0], '>', $free_after->[0], 'fewer free default pages');
    cmp_ok($free_before->[1], '>', $free_after->[1], 'fewer free compact pages');
}

sub summarize_buckets {
    my $s = shift;
    my @buks = ();
    my $is_free = 0;
    my $x = 0;
    while (exists $s->{$x . ':version'}) {
        my $is_used = $s->{$x . ':version'};
        if ($is_used == 0) {
            # version of 0 means the page is free.
            $buks[$s->{$x . ':free_bucket'}]++;
        }
        $x++;
    }
    return \@buks;
}

done_testing();

END {
    unlink $ext_path if $ext_path;
    unlink $ext_path2 if $ext_path2;
}

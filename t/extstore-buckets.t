#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

my $ext_path;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore.$$";

my $server = new_memcached("-m 256 -U 0 -o ext_page_size=8,ext_page_count=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0,ext_path=$ext_path,ext_low_ttl=60,slab_automove=1");
my $sock = $server->sock;

my $value;
{
    my @chars = ("C".."Z");
    for (1 .. 20000) {
        $value .= $chars[rand @chars];
    }
}

# fill some larger objects
{
    # interleave sets with 0 ttl vs long ttl's.
    my $keycount = 1200;
    for (1 .. $keycount) {
        print $sock "set nfoo$_ 0 0 20000 noreply\r\n$value\r\n";
        print $sock "set lfoo$_ 0 5 20000 noreply\r\n$value\r\n";
    }
    # wait for a flush
    sleep 10;
    print $sock "lru_crawler crawl all\r\n";
    <$sock>;
    sleep 2;
    # fetch
    mem_get_is($sock, "nfoo1", $value);
    # check extstore counters
    my $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_page_allocs}, '>', 0, 'at least one page allocated');
    cmp_ok($stats->{extstore_objects_written}, '>', $keycount / 2, 'some objects written');
    cmp_ok($stats->{extstore_bytes_written}, '>', length($value) * 2, 'some bytes written');
    cmp_ok($stats->{get_extstore}, '>', 0, 'one object was fetched');
    cmp_ok($stats->{extstore_objects_read}, '>', 0, 'one object read');
    cmp_ok($stats->{extstore_bytes_read}, '>', length($value), 'some bytes read');
    cmp_ok($stats->{extstore_page_reclaims}, '>', 1, 'at least two pages reclaimed');
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

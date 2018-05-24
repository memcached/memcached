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

my $server = new_memcached("-m 64 -U 0 -o ext_page_size=8,ext_page_count=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path,slab_automove=0,ext_compact_under=1");
my $sock = $server->sock;

# Wait until all items have flushed
sub wait_for_ext {
    my $sum = 1;
    while ($sum != 0) {
        my $s = mem_stats($sock, "items");
        $sum = 0;
        for my $key (keys %$s) {
            if ($key =~ m/items:(\d+):number/) {
                # Ignore classes which can contain extstore items
                next if $1 < 3;
                $sum += $s->{$key};
            }
        }
        sleep 1 if $sum != 0;
    }
}

my $value;
{
    my @chars = ("C".."Z");
    for (1 .. 20000) {
        $value .= $chars[rand @chars];
    }
}

# fill a small object
print $sock "set foo 0 0 2\r\nhi\r\n";
is(scalar <$sock>, "STORED\r\n", "stored small value");
# fetch
mem_get_is($sock, "foo", "hi");
# check extstore counters
{
    my $stats = mem_stats($sock);
    is($stats->{extstore_objects_written}, 0);
}
# fill some larger objects
{
    # set one canary value for later
    print $sock "set canary 0 0 20000 noreply\r\n$value\r\n";
    my $keycount = 1000;
    for (1 .. $keycount) {
        print $sock "set nfoo$_ 0 0 20000 noreply\r\n$value\r\n";
    }
    # wait for a flush
    wait_for_ext();
    # fetch
    # TODO: Fetch back all values
    mem_get_is($sock, "nfoo1", $value);
    # check extstore counters
    my $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_page_allocs}, '>', 0, 'at least one page allocated');
    cmp_ok($stats->{extstore_objects_written}, '>', $keycount / 2, 'some objects written');
    cmp_ok($stats->{extstore_bytes_written}, '>', length($value) * 2, 'some bytes written');
    cmp_ok($stats->{get_extstore}, '>', 0, 'one object was fetched');
    cmp_ok($stats->{extstore_objects_read}, '>', 0, 'one object read');
    cmp_ok($stats->{extstore_bytes_read}, '>', length($value), 'some bytes read');

    # Remove half of the keys for the next test.
    for (1 .. $keycount) {
        next unless $_ % 2 == 0;
        print $sock "delete nfoo$_ noreply\r\n";
    }

    my $stats2 = mem_stats($sock);
    cmp_ok($stats->{extstore_bytes_used}, '>', $stats2->{extstore_bytes_used},
        'bytes used dropped after deletions');
    cmp_ok($stats->{extstore_objects_used}, '>', $stats2->{extstore_objects_used},
        'objects used dropped after deletions');
    is($stats2->{badcrc_from_extstore}, 0, 'CRC checks successful');
    is($stats2->{miss_from_extstore}, 0, 'no misses');

    # delete the rest
    for (1 .. $keycount) {
        next unless $_ % 2 == 1;
        print $sock "delete nfoo$_ noreply\r\n";
    }
}

# fill to eviction
{
    my $keycount = 4000;
    for (1 .. $keycount) {
        print $sock "set mfoo$_ 0 0 20000 noreply\r\n$value\r\n";
    }
    # because item_age is set to 2s
    wait_for_ext();
    my $stats = mem_stats($sock);
    is($stats->{miss_from_extstore}, 0, 'no misses');
    mem_get_is($sock, "canary", undef);

    # check counters
    $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_page_evictions}, '>', 0, 'at least one page evicted');
    cmp_ok($stats->{extstore_objects_evicted}, '>', 0, 'at least one object evicted');
    cmp_ok($stats->{extstore_bytes_evicted}, '>', 0, 'some bytes evicted');
    cmp_ok($stats->{extstore_pages_free}, '<', 2, 'few pages are free');
    is($stats->{miss_from_extstore}, 1, 'exactly one miss');

    # refresh some keys so rescues happen while drop_unread == 1.
    for (1 .. $keycount / 2) {
        next unless $_ % 2 == 1;
        # Need to be fetched twice in order to bump
        print $sock "touch mfoo$_ 0 noreply\r\n";
        print $sock "touch mfoo$_ 0 noreply\r\n";
    }
    print $sock "extstore drop_unread 1\r\n";
    my $res = <$sock>;
    print $sock "extstore max_frag 0\r\n";
    $res = <$sock>;
    print $sock "extstore compact_under 4\r\n";
    $res = <$sock>;
    print $sock "extstore drop_under 3\r\n";
    $res = <$sock>;
    for (1 .. $keycount) {
        next unless $_ % 2 == 0;
        print $sock "delete mfoo$_ noreply\r\n";
    }

    sleep 4;
    $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_pages_free}, '>', 0, 'some pages now free');
    cmp_ok($stats->{extstore_compact_rescues}, '>', 0, 'some compaction rescues happened');
    cmp_ok($stats->{extstore_compact_skipped}, '>', 0, 'some compaction skips happened');
    print $sock "extstore drop_unread 0\r\n";
    $res = <$sock>;
}

# attempt to incr/decr/append/prepend or chunk objects that were sent to disk.
{
    my $keycount = 100;
    for (1 .. $keycount) {
        print $sock "set bfoo$_ 0 0 20000 noreply\r\n$value\r\n";
    }
    sleep 4;

    # incr should be blocked.
    print $sock "incr bfoo1 1\r\n";
    is(scalar <$sock>, "CLIENT_ERROR cannot increment or decrement non-numeric value\r\n", 'incr fails');

    # append/prepend *could* work, but it would require pulling the item back in.
    print $sock "append bfoo1 0 0 2\r\nhi\r\n";
    is(scalar <$sock>, "NOT_STORED\r\n", 'append fails');
    print $sock "prepend bfoo1 0 0 2\r\nhi\r\n";
    is(scalar <$sock>, "NOT_STORED\r\n", 'prepend fails');
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

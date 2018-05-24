#!/usr/bin/perl
# Networked logging tests.

use strict;
use warnings;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $ext_path;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore.$$";

my $server = new_memcached("-m 64 -U 0 -o ext_page_size=8,ext_page_count=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path,slab_chunk_max=16384,slab_automove=0,ext_compact_under=1");
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

# We're testing to ensure item chaining doesn't corrupt or poorly overlap
# data, so create a non-repeating pattern.
my @parts = ();
for (1 .. 8000) {
    push(@parts, $_);
}
my $pattern = join(':', @parts);
my $plen = length($pattern);

print $sock "set pattern 0 0 $plen\r\n$pattern\r\n";
is(scalar <$sock>, "STORED\r\n", "stored pattern successfully");
# Stash two more for later test
print $sock "set pattern2 0 0 $plen noreply\r\n$pattern\r\n";
print $sock "set pattern3 0 0 $plen noreply\r\n$pattern\r\n";
sleep 4;
mem_get_is($sock, "pattern", $pattern);

for (1..5) {
    my $size = 400 * 1024;
    my $data = "x" x $size;
    print $sock "set foo$_ 0 0 $size\r\n$data\r\n";
    my $res = <$sock>;
    is($res, "STORED\r\n", "stored some big items");
}

{
    my $max = 1024 * 1024;
    my $big = "a big value that's > .5M and < 1M. ";
    while (length($big) * 2 < $max) {
        $big = $big . $big;
    }
    my $biglen = length($big);

    for (1..40) {
        print $sock "set toast$_ 0 0 $biglen\r\n$big\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored big");
    }
    wait_for_ext();

    for (1..40) {
        mem_get_is($sock, "toast$_", $big);
    }

    my $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_page_allocs}, '>', 0, 'at least one page allocated');
    cmp_ok($stats->{extstore_objects_written}, '>', 25, 'some objects written');
    cmp_ok($stats->{extstore_bytes_written}, '>', $max * 2, 'some bytes written');
    cmp_ok($stats->{get_extstore}, '>', 5, 'multiple objects fetched');
    cmp_ok($stats->{extstore_objects_read}, '>', 0, 'one object read');
    cmp_ok($stats->{extstore_bytes_read}, '>', $max * 2, 'some bytes read');
    is($stats->{badcrc_from_extstore}, 0, 'CRC checks successful');
}

# fill to eviction
{
    my $keycount = 1250;
    for (1 .. $keycount) {
        print $sock "set mfoo$_ 0 0 $plen noreply\r\n$pattern\r\n";
        wait_for_ext() if $_ % 500 == 0;
    }
    # because item_age is set to 2s.
    wait_for_ext();

    my $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_page_evictions}, '>', 0, 'at least one page evicted');
    cmp_ok($stats->{extstore_objects_evicted}, '>', 0, 'at least one object evicted');
    cmp_ok($stats->{extstore_bytes_evicted}, '>', 0, 'some bytes evicted');
    cmp_ok($stats->{extstore_pages_free}, '<', 2, 'most pages are used');
    is($stats->{miss_from_extstore}, 0, 'no misses');

    # original "pattern" key should be gone.
    mem_get_is($sock, "pattern", undef, "original pattern key is gone");
    $stats = mem_stats($sock);
    is($stats->{miss_from_extstore}, 1, 'one extstore miss');

    print $sock "get pattern2 pattern3\r\n";
    is(scalar <$sock>, "END\r\n", "multiget double miss");
    $stats = mem_stats($sock);
    is($stats->{miss_from_extstore}, 3, 'three extstore misses');
}

# Let compaction run.
{
    for (1..40) {
        print $sock "delete toast$_ noreply\r\n" if $_ % 2 == 0;
    }

    for (1..1250) {
        # Force a read so objects don't get skipped.
        print $sock "add mfoo$_ 0 0 1 noreply\r\n1\r\n" if $_ % 2 == 1;
    }
    for (1..1250) {
        # Delete lots of objects to trigger compaction.
        print $sock "delete mfoo$_ noreply\r\n" if $_ % 2 == 0;
    }
    print $sock "extstore compact_under 4\r\n";
    my $res = <$sock>;
    print $sock "extstore drop_under 3\r\n";
    $res = <$sock>;

    sleep 4;

    my $stats = mem_stats($sock);
    cmp_ok($stats->{extstore_pages_free}, '>', 2, 'some pages now free');
    cmp_ok($stats->{extstore_compact_rescues}, '>', 0, 'some compaction rescues happened');

    # Some of the early items got evicted
    for (750..1250) {
        # everything should validate properly.
        mem_get_is($sock, "mfoo$_", $pattern) if $_ % 2 == 1;
    }
}

# test recache
{
    print $sock "extstore recache_rate 1\r\n";
    is(scalar <$sock>, "OK\r\n", "upped recache rate");

    for (1150..1250) {
        mem_get_is($sock, "mfoo$_", $pattern) if $_ % 2 == 1;
    }

    my $stats = mem_stats($sock);
    cmp_ok($stats->{recache_from_extstore}, '>', 25, 'recaching happening');
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

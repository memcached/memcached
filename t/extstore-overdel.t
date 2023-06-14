#!/usr/bin/env perl

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

my $server = new_memcached("-m 64 -U 0 -o ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_item_size=512,ext_item_age=0,ext_recache_rate=0,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=0,ext_compact_under=1,ext_max_sleep=10000");
my $sock = $server->sock;

# Wait until all items have flushed
sub wait_for_ext {
    my $target = shift || 0;
    my $sum = $target + 1;
    while ($sum > $target) {
        my $s = mem_stats($sock, "items");
        $sum = 0;
        for my $key (keys %$s) {
            if ($key =~ m/items:(\d+):number/) {
                # Ignore classes which can contain extstore items
                next if $1 < 3;
                $sum += $s->{$key};
            }
        }
        select undef, undef, undef, 0.05 if $sum > $target;
    }
}

sub rand_value {
    my $v = '';
    my $s = shift;
    my @chars = ("C".."Z");
    for (1 .. $s) {
        $v .= $chars[rand @chars];
    }
    return $v;
}
my $value = rand_value(20000);

note "fill page with same key over and over";
{
    my $rval;

    for (1 .. 100) {
        $rval = rand_value(20000);
        print $sock "set overwrite 0 0 20000 noreply\r\n$rval\r\n";
        wait_for_ext(0);
    }

    # poke the final overwrite key a few times so it will get rescued later
    print $sock "mg overwrite\r\n";
    is(scalar <$sock>, "HD\r\n");
    print $sock "mg overwrite\r\n";
    is(scalar <$sock>, "HD\r\n");

    # fill with junk to allow compaction to run.
    my $keycount = 1250;
    for (1 .. $keycount) {
        print $sock "set mfoo$_ 0 0 20000 noreply\r\n$value\r\n";
        # wait to avoid evictions
        wait_for_ext(100);
        # Keep poking the overwrite key.
        print $sock "mg overwrite\r\n";
        my $res = <$sock>;
    }
    wait_for_ext();

    my $stats = mem_stats($sock);
    is($stats->{evictions}, 0, 'no evictions');
    is($stats->{miss_from_extstore}, 0, 'no misses');

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
        #    print $sock "delete mfoo$_ noreply\r\n";
    }

    sleep 4;

    # With the bug we rescue the first seen item from the page, and since we
    # were randomizing values we could end up returning an old value (or more
    # likely none at all).
    # This should find the final randomized value has been rescued.
    mem_get_is($sock, "overwrite", $rval);
    $stats = mem_stats($sock);
    is($stats->{badcrc_from_extstore}, 0, 'CRC checks successful');
    is($stats->{miss_from_extstore}, 0, 'no misses');
    cmp_ok($stats->{extstore_pages_free}, '>', 0, 'some pages now free');
    cmp_ok($stats->{extstore_compact_rescues}, '>', 0, 'some compaction rescues happened');
    cmp_ok($stats->{extstore_compact_skipped}, '>', 0, 'some compaction skips happened');
    print $sock "extstore drop_unread 0\r\n";
    $res = <$sock>;
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

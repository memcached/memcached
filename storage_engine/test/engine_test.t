#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

# Define for each storage engine
my $storage_engine_path = "";
my $storage_engine_options = "";
my $num_threads = 1;
my $num_items_stat = "";
my $num_bytes_stat = "";



my $num_items_stat_available = (length($num_items_stat) > 0);
my $num_bytes_stat_available = (length($num_bytes_stat) > 0);

my $server = new_memcached("-m 64 -U 0 -t $num_threads -o storage_engine_path=$storage_engine_path,$storage_engine_options,ext_item_age=2,ext_recache_rate=10000");
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
        sleep 1 if $sum > $target;
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
# check engine counters
if ($num_items_stat_available) {
    my $stats = mem_stats($sock);
    is($stats->{$num_items_stat}, 0);
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

    # check engine counters
    my $stats = mem_stats($sock);
    cmp_ok($stats->{get_extstore}, '>', 0, 'one object was fetched');
    if ($num_items_stat_available) {
        is($stats->{$num_items_stat}, 1001);
    }
    if ($num_bytes_stat_available) {
        is($stats->{$num_bytes_stat}, 20085958);
    }

    # Remove half of the keys for the next test.
    for (1 .. $keycount) {
        next unless $_ % 2 == 0;
        print $sock "delete nfoo$_ noreply\r\n";
    }

    my $stats2 = mem_stats($sock);
    if ($num_items_stat_available) {
        cmp_ok($stats->{$num_items_stat}, '>', $stats2->{$num_items_stat},
            'bytes used dropped after deletions');
    }
    if ($num_bytes_stat_available) {
        cmp_ok($stats->{$num_bytes_stat}, '>', $stats2->{$num_bytes_stat},
            'objects used dropped after deletions');
    }
    is($stats2->{badcrc_from_extstore}, 0, 'CRC checks successful');
    is($stats2->{miss_from_extstore}, 0, 'no misses');

    # delete the rest
    for (1 .. $keycount) {
        next unless $_ % 2 == 1;
        print $sock "delete nfoo$_ noreply\r\n";
    }
}

# fill different values
for my $i (0..4) {
    my $value = "";
    for (1 .. 512) {
        $value .= $i;
    }
    print $sock "set key$i 0 0 512 noreply\r\n$value\r\n";
}
wait_for_ext();
for my $i (0..4) {
    my $value = "";
    for (1 .. 512) {
        $value .= $i;
    }
    mem_get_is($sock, "key$i", $value);
}

# attempt to incr/decr/append/prepend or chunk objects that were sent to disk.
{
    my $keycount = 100;
    for (1 .. $keycount) {
        print $sock "set bfoo$_ 0 0 20000 noreply\r\n$value\r\n";
    }
    wait_for_ext();

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

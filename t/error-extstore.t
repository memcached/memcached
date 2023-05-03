#!/usr/bin/env perl
# Test the "Error on get" path for extstore.
# the entire error handling code for process_get_command() never worked, and
# would infinite loop. get_extstore() can hit it sometimes.

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

my $server = new_memcached("-m 64 -I 4m -U 0 -o ext_page_size=8,ext_wbuf_size=8,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=0,ext_compact_under=1,ext_max_sleep=100000");
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

# Set some large items and let them flush to extstore.
for (1..5) {
    my $size = 3000 * 1024;
    my $data = "x" x $size;
    print $sock "set foo$_ 0 0 $size\r\n$data\r\n";
    my $res = <$sock>;
    is($res, "STORED\r\n", "stored some big items");
}

wait_for_ext();

{
    my $long_key = "f" x 512;
    print $sock "get foo1 foo2 foo3 $long_key\r\n";
    ok(scalar <$sock> =~ /CLIENT_ERROR bad command line format/, 'long key fails');
    my $stats = mem_stats($sock);
    cmp_ok($stats->{get_aborted_extstore}, '>', 1, 'some extstore queries aborted');
}

# Infinite loop: if we aborted some extstore requests, the next request would hang
# the daemon.
{
    my $size = 3000 * 1024;
    my $data = "x" x $size;
    mem_get_is($sock, "foo1", $data);
}

# Disable automatic page balancing, then move enough pages that the large
# items can no longer be loaded from extstore
{
    print $sock "slabs automove 0\r\n";
    my $res = <$sock>;
    my $source = 0;
    while (1) {
        print $sock "slabs reassign $source 1\r\n";
        $res = <$sock>;
        if ($res =~ m/NOSPARE/) {
            $source = -1;
            my $stats = mem_stats($sock, 'slabs');
            for my $key (grep { /total_pages/ } keys %$stats) {
                if ($key =~ m/(\d+):total_pages/) {
                    next if $1 < 3;
                    $source = $1 if $stats->{$key} > 1;
                }
            }
            last if $source == -1;
        }
        select undef, undef, undef, 0.10;
    }
}

# fetching the large keys should now fail.
{
    print $sock "get foo1\r\n";
    my $res = <$sock>;
    $res =~ s/[\r\n]//g;
    is($res, 'SERVER_ERROR out of memory writing get response', 'can no longer read back item');
    my $stats = mem_stats($sock);
    is($stats->{get_oom_extstore}, 1, 'check extstore oom counter');
}

# Leaving this for future generations.
# The process_get_command() function had several memory leaks.
my $LEAK_TEST = 0;
if ($LEAK_TEST) {
    my $tries = 0;
    while ($tries) {
        print $sock "slabs reassign 1 39\r\n";
        my $res = <$sock>;
        if ($res =~ m/BUSY/) {
            select undef, undef, undef, 0.10;
        } else {
            $tries--;
        }
    }
    my $long_key = "f" x 512;
    while (1) {
        print $sock "get foo1 foo2 foo3 $long_key\r\n";
        my $res = <$sock>;
    }
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

#!/usr/bin/perl
# Networked logging tests.

use strict;
use warnings;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 48 -o slab_chunk_max=16384');
my $sock = $server->sock;

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

    for (1..100) {
        print $sock "set toast$_ 0 0 $biglen\r\n$big\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored big");
        mem_get_is($sock, "toast$_", $big);
    }
}

# Test a wide range of sets.
{
    my $len = 1024 * 200;
    while ($len < 1024 * 1024) {
        my $val = "B" x $len;
        print $sock "set foo_$len 0 0 $len\r\n$val\r\n";
        is(scalar <$sock>, "STORED\r\n", "stored size $len");
        $len += 2048;
    }
}

# Test long appends and prepends.
# Note: memory bloats like crazy if we use one test per request.
{
    my $str = 'seedstring';
    my $len = length($str);
    print $sock "set appender 0 0 $len\r\n$str\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored seed string for append");
    my $unexpected = 0;
    for my $part (@parts) {
        # reduce required loops but still have a pattern.
        my $todo = $part . "x" x 10;
        $str .= $todo;
        my $len = length($todo);
        print $sock "append appender 0 0 $len\r\n$todo\r\n";
        is(scalar <$sock>, "STORED\r\n", "append $todo size $len");
        print $sock "get appender\r\n";
        my $header = scalar <$sock>;
        my $body = scalar <$sock>;
        my $end = scalar <$sock>;
        $unexpected++ unless $body eq "$str\r\n";
    }
    is($unexpected, 0, "No unexpected results during appends\n");
    # Now test appending a chunked item to a chunked item.
    $len = length($str);
    print $sock "append appender 0 0 $len\r\n$str\r\n";
    is(scalar <$sock>, "STORED\r\n", "append large string size $len");
    mem_get_is($sock, "appender", $str . $str);
    print $sock "delete appender\r\n";
    is(scalar <$sock>, "DELETED\r\n", "removed appender key");
}

{
    my $str = 'seedstring';
    my $len = length($str);
    print $sock "set prepender 0 0 $len\r\n$str\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored seed string for append");
    my $unexpected = 0;
    for my $part (@parts) {
        # reduce required loops but still have a pattern.
        $part .= "x" x 10;
        $str = $part . $str;
        my $len = length($part);
        print $sock "prepend prepender 0 0 $len\r\n$part\r\n";
        is(scalar <$sock>, "STORED\r\n", "prepend $part size $len");
        print $sock "get prepender\r\n";
        my $header = scalar <$sock>;
        my $body = scalar <$sock>;
        my $end = scalar <$sock>;
        $unexpected++ unless $body eq "$str\r\n";
    }
    is($unexpected, 0, "No unexpected results during prepends\n");
    # Now test prepending a chunked item to a chunked item.
    $len = length($str);
    print $sock "prepend prepender 0 0 $len\r\n$str\r\n";
    is(scalar <$sock>, "STORED\r\n", "prepend large string size $len");
    mem_get_is($sock, "prepender", $str . $str);
    print $sock "delete prepender\r\n";
    is(scalar <$sock>, "DELETED\r\n", "removed prepender key");
}

done_testing();

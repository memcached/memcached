#!/usr/bin/perl

use strict;
use Test::More tests => 83;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached("-X .libs/ascii_scrub.so");
my $sock = $server->sock;
my $key = 0;

for ($key = 0; $key < 40; $key++) {
    print $sock "set key$key 0 1 5\r\nvalue\r\n";
    is (scalar <$sock>, "STORED\r\n", "stored key$key");
}

for ($key = 40; $key < 80; $key++) {
    print $sock "set key$key 0 0 5\r\nvalue\r\n";
    is (scalar <$sock>, "STORED\r\n", "stored key$key");
}

sleep(2.2);
print $sock "scrub\r\n";
is (scalar <$sock>, "OK\r\n", "scrub started");
sleep(1.2);
my $stats  = mem_stats($sock, "scrub");
my $visited = $stats->{"scrubber:visited"};
my $cleaned = $stats->{"scrubber:cleaned"};

is ($visited, "80", "visited");
is ($cleaned, "40", "cleaned");

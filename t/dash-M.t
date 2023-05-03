#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-M -m 2');
my $sock = $server->sock;

my $value = "B" x 8192;
my $vallen = length($value);

my $resp = "STORED\r\n";
my $key = 0;

while($resp eq "STORED\r\n") {
    print $sock "set dash$key 0 0 $vallen\r\n$value\r\n";
    $key++;
    $resp = scalar <$sock>;
}

my $max_stored = $key - 1;

plan tests => $max_stored + 2;

print $sock "set dash$key 0 0 $vallen\r\n$value\r\n";
is(scalar <$sock>, "SERVER_ERROR out of memory storing object\r\n",
   "failed to add another one.");

my $stats = mem_stats($sock);
is($stats->{"store_no_memory"}, 2,
    "recorded store failures due to no memory");

for($key = 0; $key < $max_stored; $key++) {
    mem_get_is $sock, "dash$key", $value, "Failed at dash$key";
}

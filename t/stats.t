#!/usr/bin/perl

use strict;
use Test::More tests => 17;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;


## Output looks like this:
##
## STAT pid 16293
## STAT uptime 7
## STAT time 1174419597
## STAT version 1.2.1
## STAT pointer_size 32
## STAT rusage_user 0.012998
## STAT rusage_system 0.119981
## STAT curr_items 0
## STAT total_items 0
## STAT bytes 0
## STAT curr_connections 1
## STAT total_connections 2
## STAT connection_structures 2
## STAT cmd_get 0
## STAT cmd_set 0
## STAT get_hits 0
## STAT get_misses 0
## STAT evictions 0
## STAT bytes_read 7
## STAT bytes_written 0
## STAT limit_maxbytes 67108864

my $stats = mem_stats($sock);

# Test number of keys
is(scalar(keys(%$stats)), 22, "22 stats values");

# Test initial state
foreach my $key (qw(curr_items total_items bytes cmd_get cmd_set get_hits evictions get_misses bytes_written)) {
    is($stats->{$key}, 0, "initial $key is zero");
}

# Do some operations

print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "fooval");

my $stats = mem_stats($sock);

foreach my $key (qw(total_items curr_items cmd_get cmd_set get_hits)) {
    is($stats->{$key}, 1, "after one set/one get $key is 1");
}

#!/usr/bin/env perl
# The autocrawler should not come back to an LRU sooner than a minute when its
# expiring items all have under a minute left: histo[0] counts items expiring
# in the next 0..1 minutes, so they are all gone only after that minute.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 32 -o no_lru_crawler');
my $sock = $server->sock;

# Items expiring in 30 seconds: all of them in the first histogram bucket.
for (1 .. 100) {
    print $sock "set sfoo$_ 0 30 2\r\nok\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key");
}

my $watcher = $server->new_sock;
print $watcher "watch sysevents\n";
is(scalar <$watcher>, "OK\r\n", "watcher enabled");

print $sock "lru_crawler enable\r\n";
is(scalar <$sock>, "OK\r\n", "enabled lru crawler");

# The first autocrawl walks every LRU; the maintainer then schedules the next
# crawl of each one and logs it. Wait for the LRU of slab class 1 that holds
# the items (next_reclaims > 0).
my $next_run;
eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm 30;
    while (my $log = <$watcher>) {
        if ($log =~ m/type=lru_crawler crawler=1 lru=\w+ low_mark=\d+ next_reclaims=(\d+) since_run=\d+ next_run=(\d+)/
                && $1 > 0) {
            $next_run = $2;
            last;
        }
    }
    alarm 0;
};
is($@, '', "crawler logged the next run for slab class 1");
ok(defined $next_run && $next_run >= 60,
    "next crawl waits at least a minute (next_run=" . ($next_run // 'none') . ")");

done_testing();

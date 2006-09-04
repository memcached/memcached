#!/usr/bin/perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

$ENV{T_MEMD_INITIAL_MALLOC} = 4294967328; # 2**32 + 32  :)
$ENV{T_MEMD_SLABS_ALLOC}    = 0;  # don't preallocate slabs

my $server = new_memcached();
my $sock = $server->sock;

{
    print $sock "stats slabs\r\n";
    my %stats;
    while (<$sock>) {
        last if /^(\.|END)/;
        /^STAT (\S+) (\d+)/;
        $stats{$1} = $2;
    }
    if ($stats{'total_malloced'} eq "32") {
        plan skip_all => 'Skipping 64-bit tests on 32-bit build';
        exit 0;
    } else {
        plan tests => 1;
    }
    ok(1, "is 64 bit");
}

#!/usr/bin/perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

$ENV{T_MEMD_INITIAL_MALLOC} = "4294967328"; # 2**32 + 32  :)
$ENV{T_MEMD_SLABS_ALLOC}    = 0;  # don't preallocate slabs

my $server = new_memcached("-m 4097 -M");
my $sock = $server->sock;
my %slabs;
my %stats;

my $get_slabs = sub{
    print $sock "stats slabs\r\n";
    while (<$sock>) {
        last if /^(\.|END)/;
        /^STAT (\S+) (\d+)/;
        #print " slabs: $_";
        $slabs{$1} = $2;
    }
};

my $get_stats = sub{
    print $sock "stats\r\n";
    while (<$sock>) {
        last if /^(\.|END)/;
        /^STAT (\S+) (\d+)/;
        #print " stats ($1) = ($2)\n";
        $stats{$1} = $2;
    }
};

$get_slabs->();
$get_stats->();

if ($slabs{'total_malloced'} eq "32" || $slabs{'total_malloced'} eq "2147483647") {
    plan skip_all => 'Skipping 64-bit tests on 32-bit build';
    exit 0;
} else {
    plan tests => 6;
}

ok(1, "is 64 bit");
is($stats{'limit_maxbytes'}, "4296015872", "max bytes is 4097 MB");
is($slabs{'total_malloced'}, "4294967328", "expected (faked) value of total_malloced");
is($slabs{'active_slabs'}, 0, "no active slabs");

my $hit_limit = 0;
for (1..3) {
    my $size = 400 * 1024;
    my $data = "a" x $size;
    print $sock "set big$_ 0 0 $size\r\n$data\r\n";
    my $res = <$sock>;
    $hit_limit = 1 if $res ne "STORED\r\n";
}
ok($hit_limit, "hit size limit");

$get_slabs->();
is($slabs{'active_slabs'}, 1, "1 active slab");

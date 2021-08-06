#!/usr/bin/perl

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

if (!defined $ENV{'JEMALLOC_TEST'}) {
    plan skip_all => 'jemalloc testing is not enabled';
    exit 0;
}

my $exe = MemcachedTest::get_memcached_exe();
my $res = `ldd $exe | grep libjemalloc | wc -l`;
chomp $res;
is($res, 1);
done_testing();

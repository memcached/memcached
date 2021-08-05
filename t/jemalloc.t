#!/usr/bin/perl

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $exe = MemcachedTest::get_memcached_exe();
my $res = `ldd $exe | grep libjemalloc | wc -l`;
chomp $res;
is($res, 1);
done_testing();

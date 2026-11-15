#!/usr/bin/env perl

# Starting the daemon multiple times within one test file makes attaching GDB
# to a test difficult. We isolate those tests into this file.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

my $ext_path;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore.$$";

eval {
    my $server = new_memcached("-o ext_path=$ext_path:0m");
};
ok($@, "failed to start server with zero pages assigned");

eval {
    my $server = new_memcached("-o ext_path=$ext_path:1GB");
};
ok($@, "failed to start server with invalid path size");

my $server = new_memcached("-m 64 -U 0 -o ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=0,ext_compact_under=1,ext_max_sleep=100000");
my $sock = $server->sock;

eval {
    my $server = new_memcached("-o ext_path=$ext_path:64m");
};
ok($@, "failed to start a second server with the same file path");

done_testing();

END {
    unlink $ext_path if $ext_path;
}

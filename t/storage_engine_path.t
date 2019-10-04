#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

# Instead of doing the substitution with Autoconf, we assume that
# cwd == builddir.
use Cwd;
my $builddir = getcwd;

my $exe = "$builddir/memcached-debug";
croak("memcached binary doesn't exist.  Haven't run 'make' ?\n") unless -e $exe;
croak("memcached binary not executable\n") unless -x _;

my $ext_path = "/tmp/extstore.$$";

my $storage_engine_path = "extstore/.libs/libextstore.so";
my $args = "-m 64 -U 0 -d -o storage_engine_path=$storage_engine_path,ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=0,ext_compact_under=1";
my $pid = open(PH, "$exe $args 2>&1 1>/dev/null |");
my $err = <PH>;
print "pid: $pid\r\n";
if($err) {
    print "err: $err\r\n";
}
kill 'KILL', $pid;
is($err, undef, 'correct path');

$storage_engine_path = "extstore/.libs/libextstor.so";
$args = "-m 64 -U 0 -d -o storage_engine_path=$storage_engine_path,ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=0,ext_compact_under=1";
$pid = open(PH, "$exe $args 2>&1 1>/dev/null |");
$err = <PH>;
print "pid: $pid\r\n";
print "err: $err\r\n";
kill 'KILL', $pid;
is($err, "Error loading storage engine plugin: extstore/.libs/libextstor.so: cannot open shared object file: No such file or directory\n", 'wrong path');

done_testing();

END {
    unlink $ext_path if $ext_path;
}

#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

my $ext_path;
my $ext_path2;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore1.$$";

my $server = new_memcached("-m 256 -U 0 -o ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=100,ext_recache_rate=100,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=1,ext_max_sleep=100000");
my $sock = $server->sock;

my $value;
{
    my @chars = ("C".."Z");
    for (1 .. 20000) {
        $value .= $chars[rand @chars];
    }
}

{
    # bumping the CAS a few times by just overwriting the value
    for (1 .. 3) {
        print $sock "set foo 0 0 20000 noreply\r\n$value\r\n";
    }
    my ($cas, $val) = mem_gets($sock, "foo");
    isnt($cas, 0, "got a real cas value back");

    print $sock "extstore item_age 1\r\n";
    is(scalar <$sock>, "OK\r\n");
    wait_ext_flush($sock);

    my ($cas2, $val2) = mem_gets($sock, "foo");
    my $stats = mem_stats($sock);
    is($stats->{get_extstore}, 1, 'one object was fetched');
    is($stats->{recache_from_extstore}, 0, 'no object recached');

    is($cas, $cas2, "cas still matches");

    # Make sure we recache on the next hit.
    print $sock "extstore recache_rate 1\r\n";
    is(scalar <$sock>, "OK\r\n");
    # Make sure we don't drop back to disk immediately.
    print $sock "extstore item_age 100\r\n";
    is(scalar <$sock>, "OK\r\n");

    # Hit it once to force recache.
    my ($cas3, $val3) = mem_gets($sock, "foo");

    # Hit it again to fetch the "recached" value
    ($cas3, $val3) = mem_gets($sock, "foo");

    $stats = mem_stats($sock);
    is($stats->{recache_from_extstore}, 1, 'one object recached');

    is($cas, $cas3, "CAS values still match");
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

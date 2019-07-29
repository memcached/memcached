#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $mem_path = "/dev/shm/mc_restart.$$";

my $server = new_memcached("-m 128 -e $mem_path -I 2m");
my $sock = $server->sock;

{
    # Set some values, various sizes.
    my $cur = 2;
    my $cnt = 0;
    my $end = 2**20;
    while ($cur <= $end) {
        my $val = 'x' x $cur;
        print $sock "set foo${cnt} 0 0 $cur\r\n$val\r\n";
        like(scalar <$sock>, qr/STORED/, "stored $cur size item");
        $cur *= 2;
        $cnt++;
    }
}

$server->graceful_stop();
diag "killed, waiting";
# TODO: should add way to wait for server to fully exit..
sleep 5;

{
    $server = new_memcached("-m 128 -e $mem_path -I 2m");
    $sock = $server->sock;
    diag "reconnected";
}

{
    my $cur = 2;
    my $cnt = 0;
    my $end = 1000000;
    while ($cur < $end) {
        my $val = 'x' x $cur;
        mem_get_is($sock, 'foo' . $cnt, $val);
        $cur *= 2;
        $cnt++;
    }
}

done_testing();

END {
    unlink $mem_path if $mem_path;
}

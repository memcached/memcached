#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# NOTE: Do not use this feature on top of a filesystem, please use a ram disk!
# These tests use /tmp/ as some systems do not have or have a weirdly small
# /dev/shm.
my $mem_path = "/tmp/mc_restart.$$";

# read a invalid metadata file
{
    my $meta_path = "$mem_path.meta";
    open(my $f, "> $meta_path") || die("Can't open a metadata file.");
    eval {  new_memcached("-e $mem_path"); };
    unlink($meta_path);
    ok($@, "Died with an empty metadata file");
}

my $server = new_memcached("-m 128 -e $mem_path -I 2m");
my $sock = $server->sock;

diag "restart basic stats";
{
    my $stats = mem_stats($server->sock, ' settings');
    is($stats->{memory_file}, $mem_path);
}

diag "Set some values, various sizes.";
{
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

diag "load enough items to change hash power level";
{
    my $stats = mem_stats($sock);
    is($stats->{hash_power_level}, 16, "starting hash level is 16");
    my $todo = 2**17;
    my $good = 1;
    while ($todo--) {
        print $sock "set z${todo} 0 0 0\r\n\r\n";
        my $res = <$sock>;
        $good = 0 if ($res !~ m/STORED/);
    }

    is($good, 1, "set responses were all STORED");
    sleep 3; # sigh.
    $stats = mem_stats($sock);
    is($stats->{hash_power_level}, 17, "new hash power level is 17");

    # Now delete all these items, so the auto-restore won't cause the hash
    # table to re-inflate, but the restart code should restore the hash table
    # to where it was regardless.
    $todo = 2**17;
    $good = 1;
    while ($todo--) {
        print $sock "delete z${todo}\r\n";
        my $res = <$sock>;
        $good = 0 if ($res !~ m/DELETED/);
    }
    is($good, 1, "delete responses were all DELETED");
}

diag "Load a couple chunked items";
my $deleted_chunked_item = 0;
{
    my $cur = 768000;
    my $cnt = 0;
    my $end = $cur + 1024;
    while ($cur <= $end) {
        my $val = 'x' x $cur;
        print $sock "set chunk${cnt} 0 0 $cur\r\n$val\r\n";
        like(scalar <$sock>, qr/STORED/, "stored $cur size item");
        $cur += 50;
        $cnt++;
    }
    # delete the last one.
    $cnt--;
    $deleted_chunked_item = $cnt;
    print $sock "delete chunk${cnt}\r\n";
    like(scalar <$sock>, qr/DELETED/, "deleted $cnt from large chunked items");
}

diag "Data that should expire while stopped.";
{
    print $sock "set low1 0 5 2\r\nbo\r\n";
    like(scalar <$sock>, qr/STORED/, "stored low ttl item");
    # This one should stay.
    print $sock "set low2 0 20 2\r\nmo\r\n";
    like(scalar <$sock>, qr/STORED/, "stored low ttl item");
}

# make sure it's okay to stop with a logger watcher enabled.
{
    my $wsock = $server->new_sock;
    print $wsock "watch fetchers mutations\n";
    my $res = <$wsock>;
    is($res, "OK\r\n", "watcher enabled");
}

$server->graceful_stop();
diag "killed, waiting";
# TODO: add way to wait for server to fully exit..
sleep 10;

{
    $server = new_memcached("-m 128 -e $mem_path -I 2m");
    $sock = $server->sock;
    diag "reconnected";

    my $stats = mem_stats($sock);
    is($stats->{hash_power_level}, 17, "restarted hash power level is 17");
}

diag "low TTL item should be gone";
{
    mem_get_is($sock, 'low1', undef);
    # but this one should exist.
    mem_get_is($sock, 'low2', 'mo');
}

# initially inserted items.
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

# chunked items.
{
    my $cur = 768000;
    my $cnt = 0;
    my $end = $cur + 1024;
    while ($cur <= $end) {
        my $val = 'x' x $cur;
        if ($cnt != $deleted_chunked_item) {
            mem_get_is($sock, 'chunk' . $cnt, $val);
        }
        $cur += 50;
        $cnt++;
    }
}

done_testing();

END {
    unlink $mem_path if $mem_path;
}

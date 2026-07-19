#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use IO::Socket qw(AF_INET SOCK_STREAM);
use IO::Select;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $t = Memcached::ProxyTest->new(servers => [11811, 11812, 11813]);

my $p_srv = new_memcached('-o proxy_config=routelib,proxy_arg=./t/proxyhashdist.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);
$t->accept_backends();

my $w = $p_srv->new_sock;
print $w "watch proxyevents\r\n";
is(<$w>, "OK\r\n");

subtest 'module & farmhash' => sub {
    # Computed in bigquery by running the following query:
    #
    # WITH keys AS (SELECT FORMAT("key%d", i) AS key FROM UNNEST(GENERATE_ARRAY(0, 20)) i)
    # SELECT key, MOD(FARM_FINGERPRINT(key) & 0x7FFFFFFFFFFFFFFF, 3) FROM keys;
    my @key_mapping = (
        [ "key0", 2 ],
        [ "key1", 1 ],
        [ "key2", 1 ],
        [ "key3", 0 ],
        [ "key4", 1 ],
        [ "key5", 2 ],
        [ "key6", 1 ],
        [ "key7", 2 ],
        [ "key8", 1 ],
        [ "key9", 1 ],
        [ "key10", 1 ],
        [ "key11", 0 ],
        [ "key12", 1 ],
        [ "key13", 0 ],
        [ "key14", 0 ],
        [ "key15", 0 ],
        [ "key16", 0 ],
        [ "key17", 1 ],
        [ "key18", 2 ],
        [ "key19", 1 ],
        [ "key20", 1 ],
    );

    for my $mapping (@key_mapping) {
        my $key = $mapping->[0];
        my $idx = $mapping->[1];
        my $cmd = "mg $key\r\n";

        $t->c_send($cmd);
        $t->be_recv($idx, $cmd);
        $t->be_send($idx, "HD\r\n");
        $t->c_recv_be();
        $t->clear();
    }
};
done_testing();

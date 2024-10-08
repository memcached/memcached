#!/usr/bin/env perl

use strict;
use warnings;
use Socket qw/SO_RCVBUF/;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

plan tests => 5;

my $server = new_memcached('-o proxy_config=./t/watcher-internal.lua -t 1');
my $client = $server->sock;
my $watcher = $server->new_sock;

# This doesn't return anything.
print $watcher "watch\n";
my $res = <$watcher>;
is($res, "OK\r\n", "watcher enabled");

print $client "get foo\n";
$res = <$client>;
is($res, "END\r\n", "basic get works");

{
    my $watcher = $server->new_sock;
    print $watcher "watch deletions\n";
    is(<$watcher>, "OK\r\n", "deletions watcher enabled");

    print $client "set vfoo 0 0 4\r\nvbar\r\n";
    is(<$client>, "STORED\r\n", "stored the key");

    print $client "delete vfoo\r\n";
    is(<$client>, "DELETED\r\n", "key was deleted");

    # TODO: below line will cause the unit test to hang for now. Uncomment as soon as it works.
    # like(<$watcher>, qr/ts=\d+\.\d+\ gid=\d+ type=deleted key=vfoo cmd=delete .+ size=4/,
    #     "delete command logged with correct size");
}

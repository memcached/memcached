#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $filename = "/tmp/memcachetest$$";

if (supports_unix_socket()) {
    plan tests => 3;

    my $server = new_memcached("-s $filename");
    my $sock = $server->sock;

    ok(-S $filename, "creating unix domain socket $filename");

    # set foo (and should get it)
    print $sock "set foo 0 0 6\r\nfooval\r\n";

    is(scalar <$sock>, "STORED\r\n", "stored foo");
    mem_get_is($sock, "foo", "fooval");

    unlink($filename);

    ## Just some basic stuff for now...
} else {
    plan tests => 1;

    eval {
        my $server = new_memcached("-s $filename");
    };
    ok($@, "Died connecting to unsupported unix socket.");
}

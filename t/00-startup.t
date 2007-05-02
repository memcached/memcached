#!/usr/bin/perl

use strict;
use Test::More tests => 3;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();

ok($server, "started the server");

eval {
    my $server = new_memcached("-l fooble");
};
ok($@, "Died with illegal -l args");

eval {
    my $server = new_memcached("-l 127.0.0.1");
};
is($@,'', "-l 127.0.0.1 works");

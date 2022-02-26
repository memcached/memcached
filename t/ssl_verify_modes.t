#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Cwd;

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

my $ca_crt = getcwd() . "/t/" . MemcachedTest::CA_CRT;
my $server = new_memcached("-o ssl_verify_mode=2 -o ssl_ca_cert=$ca_crt");
# just using stats to make sure everything is working fine.
my $stats = mem_stats($server->sock);
is($stats->{accepting_conns}, 1, "client cert is verified");

done_testing();

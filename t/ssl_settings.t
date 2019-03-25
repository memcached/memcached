#!/usr/bin/perl

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

my $server = new_memcached();
my $settings = mem_stats($server->sock, ' settings');

my $cert = getcwd ."/t/". MemcachedTest::SRV_CRT;
my $key = getcwd ."/t/". MemcachedTest::SRV_KEY;

is('yes', $settings->{'ssl_enabled'});
is($cert, $settings->{'ssl_chain_cert'});
is($key, $settings->{'ssl_key'});
is(0, $settings->{'ssl_verify_mode'});
is(1, $settings->{'ssl_keyform'});
is(0, $settings->{'ssl_port'});
is('NULL', $settings->{'ssl_ciphers'});
is('NULL', $settings->{'ssl_ca_cert'});

done_testing();

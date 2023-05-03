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

my $server = new_memcached();
my $settings = mem_stats($server->sock, ' settings');

my $cert = getcwd ."/t/". MemcachedTest::SRV_CRT;
my $key = getcwd ."/t/". MemcachedTest::SRV_KEY;

is($settings->{'ssl_enabled'}, 'yes');
is($settings->{'ssl_session_cache'}, 'no');
is($settings->{'ssl_kernel_tls'}, 'no');
is($settings->{'ssl_chain_cert'}, $cert);
is($settings->{'ssl_key'}, $key);
is($settings->{'ssl_verify_mode'}, 0);
is($settings->{'ssl_keyformat'}, 1);
is($settings->{'ssl_ciphers'}, 'NULL');
is($settings->{'ssl_ca_cert'}, 'NULL');
is($settings->{'ssl_wbuf_size'}, 16384);
is($settings->{'ssl_min_version'}, 'tlsv1.2');

$server->DESTROY();
$server = new_memcached("-o ssl_wbuf_size=64");
$settings = mem_stats($server->sock, ' settings');
is($settings->{'ssl_wbuf_size'}, 65536);

done_testing();

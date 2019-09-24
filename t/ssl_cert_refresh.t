#!/usr/bin/perl

use strict;
use warnings;
use File::Copy;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

my $ca_cert = "t/" . MemcachedTest::CA_CRT;
my $cert = "t/". MemcachedTest::SRV_CRT;
my $key = "t/". MemcachedTest::SRV_KEY;
my $ca_cert_back = "t/ca_cert_back";
my $cert_back = "t/cert_back";
my $key_back = "t/pkey_back";
my $new_cert_key = "t/server.pem";
my $default_crt_ou = "OU=Subunit of Test Organization";

my $server = new_memcached("-o ssl_ca_cert=$ca_cert");
my $stats = mem_stats($server->sock);
my $pid = $stats->{pid};
my $sock = $server->sock;

# This connection should return the default server certificate
# memcached was started with.
my $cert_details =$sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/\n]*))/;
is($1, $default_crt_ou, 'Got the default cert');

# Swap a new certificate with a key
copy($ca_cert, $ca_cert_back) or die "CA cert backup failed: $!";
copy($cert, $cert_back) or die "Cert backup failed: $!";
copy($key, $key_back) or die "Key backup failed: $!";
copy($new_cert_key, $ca_cert) or die "New CA cert copy failed: $!";
copy($new_cert_key, $cert) or die "New Cert copy failed: $!";
copy($new_cert_key, $key) or die "New key copy failed: $!";

# Ask server to refresh certificates
print $sock "refresh_certs\r\n";
is(scalar <$sock>, "OK\r\n", "refreshed certificates");

# New connections should use the new certificate
$cert_details = $server->new_sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/]*))/;
is($1, 'OU=FOR TESTING PURPOSES ONLY','Got the new cert');
# Old connection should use the previous certificate
$cert_details = $sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/\n]*))/;
is($1, $default_crt_ou, 'Old connection still has the old cert');

# Just sleep a while to test the time_since_server_cert_refresh as it's counted
# in seconds.
sleep 2;
$stats = mem_stats($sock);

# Restore and ensure previous certificate is back for new connections.
move($ca_cert_back, $ca_cert) or die "CA cert restore failed: $!";
move($cert_back, $cert) or die "Cert restore failed: $!";
move($key_back, $key) or die "Key restore failed: $!";
print $sock "refresh_certs\r\n";
is(scalar <$sock>, "OK\r\n", "refreshed certificates");


$cert_details = $server->new_sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/\n]*))/;
is($1, $default_crt_ou, 'Got the old cert back');

my $stats_after = mem_stats($sock);

# We should see last refresh time is reset; hence the new
# time_since_server_cert_refresh should be less.
cmp_ok($stats_after->{time_since_server_cert_refresh}, '<',
    $stats->{time_since_server_cert_refresh}, 'Certs refreshed');

done_testing();

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

my $cert = "t/cert";
my $key = "t/pkey";
my $cert_back = "t/cert_back";
my $key_back = "t/pkey_back";
my $new_cert_key = "t/server.pem";

my $server = new_memcached();
my $stats = mem_stats($server->sock);
my $pid = $stats->{pid};

# This connection should return the default server certificate
# memcached was started with.
my $cert_details =$server->sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/]*))/;
is($1, 'OU=TestDev');

# Swap a new certificate with a key
copy($cert, $cert_back) or die "Cert backup failed: $!";
copy($key, $key_back) or die "Key backup failed: $!";
copy($new_cert_key, $cert) or die "New Cert copy failed: $!";
copy($new_cert_key, $key) or die "New key copy failed: $!";
# Signal the process to refresh certificates
kill 'SIGUSR1', $pid or die "Couldn't signal the process $pid : $!";
# New connections should use the new certificate
$cert_details = $server->new_sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/]*))/;
is($1, 'OU=FOR TESTING PURPOSES ONLY');
# Old connection should use the previous certificate
$cert_details =$server->sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/]*))/;
is($1, 'OU=TestDev');

# Restore and ensure previous certificate is back for new connections.
move($cert_back, $cert) or die "Cert restore failed: $!";
move($key_back, $key) or die "Key restore failed: $!";
kill 'SIGUSR1', $pid or die "Couldn't signale the process $pid : $!";

$cert_details = $server->new_sock->dump_peer_certificate();
$cert_details =~ m/(OU=([^\/]*))/;
is($1, 'OU=TestDev');

done_testing();

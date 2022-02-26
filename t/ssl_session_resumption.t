#!/usr/bin/env perl

use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

my $server;
my $sock;
my $stats;

my $session_cache = eval qq{ IO::Socket::SSL::Session_Cache->new(1); };

### Disabled SSL session cache

$server = new_memcached();
$stats = mem_stats($server->sock);
is($stats->{ssl_new_sessions}, undef,
    "new SSL sessions not recorded when session cache is disabled");
my $disabled_initial_total_conns = $stats->{total_connections};

$sock = $server->new_sock($session_cache, 'TLSv1_2');
$stats = mem_stats($sock);
cmp_ok($stats->{total_connections}, '>', $disabled_initial_total_conns,
    "client-side session cache is noop in establishing a new connection");
is($sock->get_session_reused(), 0, "client-side session cache is unused");

### Enabled SSL session cache

$server = new_memcached("-o ssl_session_cache");
# Support for session caching in IO::Socket::SSL for TLS v1.3 is incomplete.
# Here, we will deliberately force TLS v1.2 to test session caching.
$sock = $server->new_sock($session_cache, 'TLSv1_2');
$stats = mem_stats($sock);
cmp_ok($stats->{total_connections}, '>', 0, "initial connection is established");
SKIP: {
    skip "sessions counter accuracy requires OpenSSL 1.1.1 or newer", 1;
    cmp_ok($stats->{ssl_new_sessions}, '>', 0, "successful new SSL session");
}
my $enabled_initial_ssl_sessions = $stats->{ssl_new_sessions};
my $enabled_initial_total_conns = $stats->{total_connections};

# Create a new client with the same session cache
$sock = $server->new_sock($session_cache, 'TLSv1_2');
$stats = mem_stats($sock);
cmp_ok($stats->{total_connections}, '>', $enabled_initial_total_conns,
    "new connection is established");
is($stats->{ssl_new_sessions}, $enabled_initial_ssl_sessions,
    "no new SSL sessions are created on the server");
is($sock->get_session_reused(), 1,
    "client-persisted session is reused");

done_testing();

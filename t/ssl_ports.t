#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

my $tcp_port = free_port();
my $ssl_port = free_port();
my $mtls_port = free_port();

my $server = new_memcached("-l notls:127.0.0.1:$tcp_port,127.0.0.1:$ssl_port,mtls:127.0.0.1:$mtls_port", $ssl_port);
my $sock = $server->sock;

# Make sure we can talk over SSL
print $sock "set foo:123 0 0 16\r\nfoo set over SSL\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");


#.. and TCP
my $tcp_sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$tcp_port");
mem_get_is($tcp_sock, "foo:123", "foo set over SSL");

# verify mTLS failure
# not trying very hard but: if the above works and this doesn't, it's going to
# be the peer cert. If someone wants to tryhard you can try inspecting
# $SSL_ERROR and/or checking `watch connevents` stream
my $mtls_sock = $server->new_nocert_tls_sock($mtls_port, 'TLSv1_3');
print $mtls_sock "version\r\n";
is(scalar <$mtls_sock>, undef, "failed to connect without peer cert");

done_testing()

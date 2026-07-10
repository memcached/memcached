#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Socket qw(AF_INET SOCK_STREAM);
use IO::Socket::INET;
use IO::Socket::SSL;
use IO::Select;
use Data::Dumper qw/Dumper/;

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

if (!supports_tls_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my @mtls;
my $bad_com = 'bad.com';

sub _testing {
    my ($tls_type, $server_cert, $cert, $ssl_verify, $check_hostname, $options,  $verify_name) = @_;

    my $mem = Memcached::TLSTest->new(-cert_name => $server_cert, -memcached_tls => $tls_type);
    my $port = $mem->{-memcached_ports}->{$tls_type};
    $mem->start_memcached();

    my $proxy = Memcached::ProxyRoutelibTLS->new(-cert_name => $cert,
                                                 -ssl_verify_mode => $ssl_verify,
                                                 -check_hostnames => ($check_hostname ? 1 : 0),
                                                 -routelib_lua => "./t/proxyroutelibtls.lua",
                                                 -routelib_backeds_lua => "$Bin/proxyroutelibtls_backends.lua",
                                                 -memcached_objs => [$mem],
                                                 ($verify_name ? (-ssl_verify_name => $verify_name) : ()),
                                                 -options => $options || "",
                                                 );

    # Check verify certificate in mtls2 and with bad server name
    if (@mtls && scalar(@{$verify_name || []}) == 1 && $verify_name->[0] eq $bad_com) {
        $cert = undef;
        $ssl_verify = SSL_VERIFY_NONE;
    }

    $proxy->basic_testing($cert, $server_cert, $tls_type, $ssl_verify, $check_hostname);
}

sub test_code {
    my ($tls_type, $server_cert, $cert, $ssl_verify, $check_hostname) = @_;

    # For mtls2 also check verification server names in certificate
    if ("$tls_type" eq "mtls2" && "$server_cert" eq "server" && "$cert" eq "client") {
        @mtls = ($tls_type, $server_cert, $cert, $ssl_verify, $check_hostname);
    }

    _testing($tls_type, $server_cert, $cert, $ssl_verify, $check_hostname);
}

Memcached::TLSTest::test_loop(\&test_code);

# Verify CN names test for mtls2
my $test_com = "test.com";
my $alt_com = "alt.test.com";
if (@mtls) {
    my $options;
    foreach my $ra ([$test_com], [$alt_com], [$test_com, $alt_com], [$bad_com, $test_com], [$bad_com]) {
        subtest "Verify name '" . join(":", @$ra) . "' for ssl type 'mtls2'" => sub {
            _testing(@mtls, $options, $ra);
        };
    }
}

done_testing();

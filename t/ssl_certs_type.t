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
use Net::SSLeay;
use Time::Piece;

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

sub _certification_check {
    my %args = (
        -name => undef,
        -name_server => undef,
        -type => undef,
        -port => undef,
        -ssl_verify_mode => SSL_VERIFY_NONE,
        -check_hostname => 1,
        @_);

    if ($args{-type} eq "notls") {
        return IO::Socket::INET->new(PeerAddr => "127.0.0.1:" . $args{-port});
    }

    my $cert_client = $args{-name} ? Memcached::TLSTest::get_cert($args{-name}) : {};
    my $cert_server = Memcached::TLSTest::get_cert($args{-name_server});

    my %opts = (PeerAddr => "127.0.0.1:" . $args{-port}, SSL_verify_mode => $args{-ssl_verify_mode});
    if ($args{-name}) {
        $opts{SSL_ca_file} = Memcached::TLSTest::get_cert("ca_cert");
        $opts{SSL_cert_file} = $cert_client->{ssl_chain_cert};
        $opts{SSL_key_file} = $cert_client->{ssl_key};
    }
    if ($args{-check_hostname}) {
        $opts{SSL_hostname} = $cert_server->{cn};
    }

    my $sock = IO::Socket::SSL->new(%opts);
    # Server contain expired certificate
    if ($args{-ssl_verify_mode} != SSL_VERIFY_NONE &&
        ($args{-name_server} eq "expired" || !$args{-name})) {
        ok(!ref($sock), "Socket check if fail on expired server certificate");
        ok($SSL_ERROR =~ /certificate verify failed/, "Check server certificate verify failed");
        return;
    }

    # Get certificate
    my $cert;
    eval {
        $cert = $sock->peer_certificate;
    };
    if (!$cert && !$args{-name} && $args{-type} =~ /^mtls/) {
        ok(1, "Peer certificate failed");
        return undef;
    }

    # Dump certificate
    my $cert_details;
    eval {
        $cert_details = $sock->dump_peer_certificate();
    };
    if ($@ && $@ =~ /hostname verification failed/) {
        ok(!$opts{SSL_hostname}, "Hostname verification failed on missed SSL_hostname");
        return undef;
    }

    $cert_details =~ m/(OU=([^\/\n]*))/;
    is($1, Memcached::TLSTest::default_crt_ou, 'Got the default cert');

    # Verify hostname
    if ($opts{SSL_hostname}) {
        my %hosts = map {$_ => undef} @{$cert_server->{alt}};
        $hosts{$cert_server->{cn}} = undef if ($args{-name_server} ne "expired");

        foreach my $host (sort keys %hosts) {
            ok($sock->verify_hostname($host), "Verify hostname '$host'");
        }
        ok(!$sock->verify_hostname("bad.com"), "Verify hostname failed 'bad.com'");
    }

    return $sock;
}

sub _testing {
    my ($sock, $cert_name, $type, $ssl_verify) = @_;

    return unless $sock;

    my $str;
    eval {
        # macOS: Net::SSLeay dies unexpectedly when mTLS is enabled with missing or expired client certificate
        local $SIG{PIPE}  = sub { die "Signal PIPE $!" };
        print $sock "set foo 0 0 6\r\nfooval\r\n";
        $str = scalar <$sock>;
    };
    if ($type =~ /^mtls/ && (!$cert_name || $cert_name eq "expired")) {
        ok(!$str, "Stored for '$type' should fail");
        return;
    } else {
        is($str, "STORED\r\n", "stored foo");
    }

    mem_get_is($sock, "foo", "fooval");

    print $sock "set foo 0 0 3\r\nnew\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored foo = 'new'");
    mem_get_is($sock, "foo", 'new');
}

sub test_code {
    my ($tls_type, $server_cert, $cert, $ssl_verify, $check_hostname) = @_;

    my $mem = Memcached::TLSTest->new(-cert_name => $server_cert, -memcached_tls => $tls_type);
    my $port = $mem->{-memcached_ports}->{$tls_type};
    $mem->start_memcached;
    my $sock =_certification_check(-name => $cert,
                                   -name_server => $server_cert,
                                   -type => $tls_type,
                                   -port =>$port,
                                   -ssl_verify_mode => $ssl_verify,
                                   -use_certs => ($cert ? 1 : 0),
                                   -check_hostnames => ($check_hostname ? 1 : 0),
                                    );
    _testing($sock, $cert, $tls_type, $ssl_verify);
}

Memcached::TLSTest::test_loop(\&test_code);

done_testing();

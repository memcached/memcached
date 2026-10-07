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
use JSON;

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

if (!supports_tls_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

if (!$ENV{MEMTIER}) {
    plan skip_all => "Memtier not setup in environment as variable 'MEMTIER'";
    exit 0;
}

if (!-x $ENV{MEMTIER}) {
    plan skip_all => "Memtier is not executable in '$ENV{MEMTIER}'";
    exit 0;
}

my @files = ();
my $run_cnt = 0;
my $timeduration = 0;
sub _memtier {
    my $json_file = "/tmp/memtier-$$-$run_cnt.json";
    my $out_file = "/tmp/memtier-$$-$run_cnt.out";
    my @opts = ($ENV{MEMTIER},
                "--out-file=$out_file",
                "--protocol=memcache_text",
                "--clients=100",
                "--threads=4",
                "--requests=1000",
                "--key-pattern=S:S",
                "--data-size=256",
                "--hide-histogram",
                "--json-out-file=$json_file",
            );

    foreach (@_) {
        push (@opts, "--server=127.0.0.1", "--port=$_");
    }
    #push (@opts, "--cluster-mode") if scalar(@_) > 1;
    push (@files, $json_file, $out_file);
    $run_cnt ++;

    system(@opts);

    my $json_text = do {
        open(my $json_fh, "<:encoding(UTF-8)", $json_file)
             or die("Can't open \"$json_file\": $!\n");
        local $/;
        <$json_fh>
    };

    my $json = JSON->new;
    my $data = $json->decode($json_text);

    my $tduration = $data->{'ALL STATS'}->{'Runtime'}->{'Total duration'} / 1000;
    diag "TimeDuration: $tduration";
    if ($timeduration) {
        diag "TimeDuration to main: " . sprintf("%.2f %%", ( ($tduration / $timeduration) - 1.0) * 100.0);
    }

    my $stats = $data->{'ALL STATS'}->{Totals};
    foreach my $k ("KB/sec", "Min Latency", "Count", "Ops/sec") {
        diag "$k: " , $stats->{$k};
    }


    return $tduration;
}

$ENV{SERVER_CERTS} ||= "server";
$ENV{CLIENT_CERTS} ||= "client";
$ENV{CHECK_HOSTNAMES} ||= 0;
my $memcached_cnt = $ENV{MEMCACHED_CNT} || 1;

sub test_code {
    my ($tls_type, $server_cert, $cert, $ssl_verify, $check_hostname) = @_;

    my @arr_mems = ();
    for my $i (1 .. $memcached_cnt) {
        my $mem = Memcached::TLSTest->new(-cert_name => $server_cert, -memcached_tls => $tls_type);
        my $port = $mem->{-memcached_ports}->{$tls_type};
        $mem->start_memcached($ENV{MEMCACHED_OPTS});
        push(@arr_mems, $mem);
    }

    my $proxy = Memcached::ProxyRoutelibTLS->new(-cert_name => $cert,
                                                 -ssl_verify_mode => $ssl_verify,
                                                 -check_hostnames => ($check_hostname ? 1 : 0),
                                                 -routelib_lua => "./t/proxyroutelibtls_memtier.lua",
                                                 -routelib_backeds_lua => "$Bin/proxyroutelibtls_memtier_backends.lua",
                                                 -memcached_objs => \@arr_mems,
                                                 -options => $ENV{PROXY_OPTS},
                                                 );
    if ($proxy->basic_testing($cert, $server_cert, $tls_type, $ssl_verify, $check_hostname)) {
        _memtier($proxy->{-port});
        my $cnt = 0;
        foreach my $mem (@arr_mems) {
            my $stats = MemcachedTest::mem_stats($mem->{-server}->sock);
            diag "Total items(" . $cnt++ . "): " . $stats->{total_items};
        }
    }
}

# First run on memcached without TLS
{
    my $mem = Memcached::TLSTest->new(-cert_name => "server", -memcached_tls => "notls");
    $mem->start_memcached;
    $timeduration = _memtier($mem->{-memcached_ports}->{"notls"});
    my $stats = MemcachedTest::mem_stats($mem->{-server}->sock);
    diag "Total items:" . $stats->{total_items};
}

# Test proxy
Memcached::TLSTest::test_loop(\&test_code, [SSL_VERIFY_NONE]);

done_testing();

END {
    foreach my $f (@files) {
        if ($ENV{NOT_REMOVE_FILE}) {
            print STDERR "File '$f' not removed\n";
        } else {
            unlink($f);
        }
    }
}

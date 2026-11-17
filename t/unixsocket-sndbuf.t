#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $filename = "/tmp/memcachetest$$";

if (!supports_unix_socket()) {
    plan skip_all => "unix sockets not supported";
    exit 0;
}

plan tests => 9;

my $size = 300 * 1024;
my $val = "x" x (250 * 1024);
my $reply = "VALUE big 0 " . length($val) . "\r\n$val\r\nEND\r\n";

# bytes_written counts every connection, including the stats replies used to
# read it. Returns the counter and the size of the reply that carried it.
sub bytes_written {
    my $s = shift;
    my ($written, $len) = (0, 0);
    print $s "stats\r\n";
    while (my $line = <$s>) {
        $len += length($line);
        last if $line eq "END\r\n";
        $written = $1 if $line =~ /^STAT bytes_written (\d+)/;
    }
    return ($written, $len);
}

my $server = new_memcached("-s $filename -o unix_sndbuf=$size");
my $sock = $server->sock;

my $settings = mem_stats($sock, "settings");
is($settings->{unix_sndbuf}, $size, "unix_sndbuf visible in stats settings");

print $sock "set big 0 0 " . length($val) . "\r\n$val\r\n";
is(scalar <$sock>, "STORED\r\n", "stored big value");

# A reply larger than the default send buffer but smaller than the configured
# one is written in full while the client is not reading.
my $other = $server->new_sock;
my ($start, $overhead) = bytes_written($other);
print $sock "get big\r\n";
SKIP: {
    skip "default unix send buffer size is OS specific", 1 unless $^O eq 'linux';
    my $sent = 0;
    for (1..20) {
        select(undef, undef, undef, 0.05);
        my ($now, $len) = bytes_written($other);
        $sent = $now - $start - $overhead;
        $overhead += $len;
        last if $sent >= length($reply);
    }
    is($sent, length($reply), "whole reply written without the client reading");
}

is(scalar <$sock>, "VALUE big 0 " . length($val) . "\r\n", "reply header");
my $got = '';
read($sock, $got, length($val));
is($got, $val, "reply value intact");

# The main thread calls setsockopt() after accept(): seccomp has to allow it.
SKIP: {
    skip "privilege drop not supported", 1 if enabled_tls_testing() || !supports_drop_priv();
    my $priv = new_memcached("-s $filename-priv -o drop_privileges,unix_sndbuf=$size");
    my $psock = $priv->sock;
    print $psock "set foo 0 0 6\r\nfooval\r\n";
    is(scalar <$psock>, "STORED\r\n", "connection accepted with drop_privileges");
    unlink("$filename-priv");
}

for my $bad (-1, 2147483648, 4294967297) {
    eval { new_memcached("-s $filename-bad -o unix_sndbuf=$bad"); };
    ok($@, "unix_sndbuf=$bad is rejected");
    unlink("$filename-bad");
}

unlink($filename);

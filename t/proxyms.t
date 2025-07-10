#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Socket qw(AF_INET SOCK_STREAM);
use IO::Select;
use Data::Dumper qw/Dumper/;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $p_srv = new_memcached('-o proxy_config=./t/proxyms.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

my $w = $p_srv->new_sock;
print $w "watch proxyevents\r\n";
is(<$w>, "OK\r\n");

# Slow string generator.
sub rand_string {
    my $len = shift;
    my $val = '';
    my @chars = ("A".."Z");
    for (1 .. $len) {
        $val .= $chars[rand @chars];
    }
    return $val;
}

my $req_count = 3;
my @cmds = ();
for (1 .. $req_count) {
    my $key = rand_string(100);
    my $cmd = "ms $key 203 c T10 O$_\r\n";
    my $val = rand_string(203) . "\r\n";
    push(@cmds, $cmd, $val);
}
my $rendered = join('', @cmds);
# Add in one more command with a partial payload
$rendered .= "ms " . rand_string(100) . " 203 c T10 O999\r\n";
$rendered .= rand_string(103);
my $payload_final = rand_string(100) . "\r\n";

# Generate N set requests that fit into one network read (< 16kb)
# Add in a third which fails partway through a set payload
# With the pause, the first N requests will get processed, dispatched to the
# backend, and completed instantly since the backend is down.
# Then we send the rest of the payload. With the bug we'll end up with an out
# of sync state machine and different errors.
subtest 'batch ms with split requests' => sub {
    syswrite($ps, $rendered, length($rendered));
    # Ensure memcached picks up the initial partial buffer.
    sleep 0.5;
    syswrite($ps, $payload_final, length($payload_final));
    for my $n (1 .. $req_count+1) {
        my $resline = scalar <$ps>;
        is($resline, "SERVER_ERROR backend failure\r\n", "expected error");
    }
};

# With the bug, we resume the conn state machine and clobber the pending
# request that was waiting for a payload. Leaks the actvie request.
subtest 'batch ms with closed client' => sub {
    # Get a new client so we can close it.
    my $d = $p_srv->new_sock;
    $d->autoflush(1);
    syswrite($d, $rendered, length($rendered));
    # Wait for IO execution
    sleep 0.5;
    $d->close();

    my $stats = mem_stats($ps);
    is($stats->{proxy_req_active}, 0, "no leaked requests");
};

done_testing();

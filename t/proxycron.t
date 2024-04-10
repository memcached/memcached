#!/usr/bin/env perl
# Basic testing of cron functionality.

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

my $p_srv = new_memcached('-o proxy_config=./t/proxycron.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

sub wait_reload {
    my $w = shift;
    while (my $line = <$w>) {
        if ($line =~ m/type=proxy_conf status=done/) {
            last;
        }
    }
    pass("reload complete");
}

# The crons will do some fiddling then issue a self-reload twice.
subtest 'wait for reload' => sub {
    my $w = $p_srv->new_sock;
    print $w "watch proxyevents\n";
    is(<$w>, "OK\r\n", "watcher enabled");

    wait_reload($w);
    wait_reload($w);
    my $stats = mem_stats($ps);
    cmp_ok($stats->{proxy_config_cron_runs}, '>', 3, "crons ran");
    is($stats->{proxy_config_cron_fails}, 0, "no crons failed");
};

done_testing();

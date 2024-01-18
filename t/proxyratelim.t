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

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $p_srv = new_memcached('-o proxy_config=./t/proxyratelim.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

{
    my $x = 10;
    while ($x--) {
        print $ps "mg na\r\n";
        my $res = scalar <$ps>;
        last if $res =~ m/SERVER_ERROR/;
    }
    cmp_ok($x, '>', 0, "hit rate limit without trying too many times");
    sleep 0.5;
    print $ps "mg na\r\n";
    is(scalar <$ps>, "SERVER_ERROR slow down\r\n", "still blocked after short sleep");
    sleep 3;
    print $ps "mg na\r\n";
    is(scalar <$ps>, "HD\r\n", "not blocked after longer sleep");
}

{
    my $x = 10;
    while ($x--) {
        print $ps "get na\r\n";
        my $res = scalar <$ps>;
        last if $res =~ m/SERVER_ERROR/;
    }
    cmp_ok($x, '>', 0, "global hit rate limit without trying too many times");
    sleep 0.5;
    print $ps "get na\r\n";
    is(scalar <$ps>, "SERVER_ERROR global slow down\r\n", "global still blocked after short sleep");
    sleep 3;
    print $ps "get na\r\n";
    is(scalar <$ps>, "END\r\n", "global not blocked after longer sleep");

}

done_testing();

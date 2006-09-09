#!/usr/bin/perl

use strict;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $expire;

sub wait_for_early_second {
    use Time::HiRes ();
    my $tsh = Time::HiRes::time();
    my $ts = int($tsh);  # in case time was overloaded to be hires.
    return if ($tsh - $ts) < 0.5;
    while (1) {
        my $t = int(time());
        return if $t != $ts;
        select undef, undef, undef, 0.10;  # 1/10th of a second sleeps until time changes.
    }
}

wait_for_early_second();

print $sock "set foo 0 1 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
sleep(1.5);
mem_get_is($sock, "foo", undef);

$expire = time() - 1;
print $sock "set foo 0 $expire 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", undef, "already expired");

$expire = time() + 1;
print $sock "set foo 0 $expire 6\r\nfoov+1\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "foov+1");
sleep(2.2);
mem_get_is($sock, "foo", undef, "now expired");


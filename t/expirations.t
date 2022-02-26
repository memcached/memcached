#!/usr/bin/env perl

use strict;
use Test::More tests => 41;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $expire;

sub wait_for_early_second {
    my $have_hires = eval "use Time::HiRes (); 1";
    if ($have_hires) {
        my $tsh = Time::HiRes::time();
        my $ts = int($tsh);
        return if ($tsh - $ts) < 0.5;
    }

    my $ts = int(time());
    while (1) {
        my $t = int(time());
        return if $t != $ts;
        select undef, undef, undef, 0.10;  # 1/10th of a second sleeps until time changes.
    }
}

wait_for_early_second();

# set&add expiration test
print $sock "set foo 0 3 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
mem_move_time($sock, 3);
mem_get_is($sock, "foo", undef);

$expire = time() - 1;
print $sock "set foo 0 $expire 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", undef, "already expired");

$expire = time() + 4;
print $sock "set foo 0 $expire 6\r\nfoov+1\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "foov+1");
mem_move_time($sock, 4);
mem_get_is($sock, "foo", undef, "now expired");

$expire = time() - 20;
print $sock "set boo 0 $expire 6\r\nbooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored boo");
mem_get_is($sock, "boo", undef, "now expired");

$expire = -1;
print $sock "set boo 0 $expire 6\r\nbooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored boo");
mem_get_is($sock, "boo", undef, "now expired");

print $sock "add add 0 2 6\r\naddval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored add");
mem_get_is($sock, "add", "addval");

print $sock "add add 0 2 7\r\naddval2\r\n";
is(scalar <$sock>, "NOT_STORED\r\n", "add failure");
mem_move_time($sock, 2);

print $sock "add add 0 2 7\r\naddval3\r\n";
is(scalar <$sock>, "STORED\r\n", "stored add again");
mem_get_is($sock, "add", "addval3");

# touch expiration test
print $sock "set tch 0 0 8\r\ntouchval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored tch");

$expire = time() - 1;
print $sock "touch tch $expire\r\n";
is(scalar <$sock>, "TOUCHED\r\n", "touched tch");
mem_get_is($sock, "touch", undef, "now expired");

print $sock "set tch 0 0 8\r\ntouchval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored tch");

$expire = time() + 1;
print $sock "touch tch $expire\r\n";
is(scalar <$sock>, "TOUCHED\r\n", "touched tch");
mem_move_time($sock, 1);
mem_get_is($sock, "touch", undef, "now expired");

print $sock "set tch 0 0 8\r\ntouchval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored tch");

$expire = -1;
print $sock "touch tch $expire\r\n";
is(scalar <$sock>, "TOUCHED\r\n", "touched tch");
mem_get_is($sock, "touch", undef, "now expired");

# get and touch expiration test
print $sock "set gat 0 0 6\r\ngatval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored gat");

$expire = time() - 1;
print $sock "gat $expire gat\r\n";
is(scalar <$sock>, "VALUE gat 0 6\r\n","get and touch gat");
is(scalar <$sock>, "gatval\r\n","value");
is(scalar <$sock>, "END\r\n", "end");
mem_get_is($sock, "gat", undef, "now expired");

print $sock "set gat 0 0 6\r\ngatval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored gat");

$expire = time() + 1;
print $sock "gat $expire gat\r\n";
is(scalar <$sock>, "VALUE gat 0 6\r\n","get and touch gat");
is(scalar <$sock>, "gatval\r\n","value");
is(scalar <$sock>, "END\r\n", "end");
mem_move_time($sock, 1);
mem_get_is($sock, "gat", undef, "now expired");


print $sock "set gat 0 0 6\r\ngatval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored gat");

$expire = -1;
print $sock "gat $expire gat\r\n";
is(scalar <$sock>, "VALUE gat 0 6\r\n","get and touch gat");
is(scalar <$sock>, "gatval\r\n","value");
is(scalar <$sock>, "END\r\n", "end");
mem_get_is($sock, "gat", undef, "now expired");

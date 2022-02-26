#!/usr/bin/env perl

use strict;
use Test::More tests => 27;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $expire;

print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
print $sock "flush_all\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");
mem_get_is($sock, "foo", undef);

# Test flush_all with zero delay.
print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval");
print $sock "flush_all 0\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all");
mem_get_is($sock, "foo", undef);

# check that flush_all doesn't blow away items that immediately get set
print $sock "set foo 0 0 3\r\nnew\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo = 'new'");
mem_get_is($sock, "foo", 'new');

# and the other form, specifying a flush_all time...
my $expire = time() + 2;
print $sock "flush_all $expire\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all in future");

print $sock "set foo 0 0 4\r\n1234\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo = '1234'");
mem_get_is($sock, "foo", '1234');
sleep(5);
mem_get_is($sock, "foo", undef);

print $sock "set foo 0 0 5\r\n12345\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo = '12345'");
mem_get_is($sock, "foo", '12345');
print $sock "flush_all 86400\r\n";
is(scalar <$sock>, "OK\r\n", "did flush_all for far future");
# Check foo still exists.
mem_get_is($sock, "foo", '12345');
print $sock "set foo2 0 0 5\r\n54321\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo2 = '54321'");
mem_get_is($sock, "foo", '12345');
mem_get_is($sock, "foo2", '54321');

# Test invalid argument
print $sock "flush_all invalid\r\n";
is(scalar <$sock>, "CLIENT_ERROR invalid exptime argument\r\n");

# Test -F option which disables flush_all
$server = new_memcached('-F');
$sock = $server->sock;

print $sock "set foo 0 0 7\r\nfooval2\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");

mem_get_is($sock, "foo", "fooval2");
print $sock "flush_all\r\n";
is(scalar <$sock>, "CLIENT_ERROR flush_all not allowed\r\n", "flush_all was not allowed");
mem_get_is($sock, "foo", "fooval2");

# Test that disabling CAS makes flush_all less accurate.
# Due to lock ordering issues we can no longer evict items newer than
# oldest_live, so we rely on the CAS counter for an exact cliff. So disabling
# CAS now means all items set in the same second will fail to set.
$server = new_memcached('-C');
$sock = $server->sock;

my $failed_nocas = 0;
# Running this 100,000 times failed the test a handful of times. 50 tries
# should be enough.
for (1..50) {
    print $sock "flush_all 0\r\n";
    my $foo = scalar <$sock>;
    print $sock "set foo 0 0 3\r\nnew\r\n";
    $foo = scalar <$sock>;
    print $sock "get foo\r\n";
    my $line = scalar <$sock>;
    if ($line =~ /^VALUE/) {
        $line = scalar <$sock>;
        $line = scalar <$sock>;
        print STDERR "Succeeded!!!\n";
        next;
    } elsif ($line =~ /^END/) {
        $failed_nocas++;
        last;
    }
}
is($failed_nocas, 1, "failed to set value after flush with no CAS at least once");

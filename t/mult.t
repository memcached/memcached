#!/usr/bin/env perl

use strict;
use Test::More tests => 9;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

# Store a number to the 'nummult' key.
print $sock "set nummult 0 0 1\r\n2\r\n";
is(scalar <$sock>, "STORED\r\n", "stored nummult");
mem_get_is($sock, "nummult", 2, "stored 2");

# MULT 2*2=4.
print $sock "mult nummult 2\r\n";
is(scalar <$sock>, "4\r\n", "* 2 = 4");
mem_get_is($sock, "nummult", 4);

### MULT a number that overflows.
printf $sock "set bigmult 0 0 %d\r\n18446744073709551615\r\n", length("18446744073709551615");
is(scalar <$sock>, "STORED\r\n", "stored 2**64-1");
print $sock "mult bigmult 2\r\n";
is(scalar <$sock>,
    "CLIENT_ERROR multiply would overflow\r\n",
    "can't multiply a number that overflows");

# MULT a bogus key.
print $sock "mult bogus 3\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "can't mult bogus key");

# MULT a text key.
print $sock "set textmult 0 0 2\r\nhi\r\n";
is(scalar <$sock>, "STORED\r\n", "stored hi");
print $sock "mult textmult 2\r\n";
is(scalar <$sock>,
    "CLIENT_ERROR cannot multiply non-numeric value\r\n",
    "hi * 2 = 0");

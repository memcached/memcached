#!/usr/bin/perl
# Ensure get and gets can mirror flags + CAS properly when not inlining the
# ascii response header.

use strict;
use Test::More tests => 17;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-o no_inline_ascii_resp');
my $sock = $server->sock;

# 0 flags and size
print $sock "set foo 0 0 0\r\n\r\n";
is(scalar <$sock>, "STORED\r\n", "stored");

mem_get_is($sock, "foo", "");

for my $flags (0, 123, 2**16-1, 2**31, 2**32-1) {
    print $sock "set foo $flags 0 6\r\nfooval\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored foo");
    mem_get_is({ sock => $sock,
                 flags => $flags }, "foo", "fooval", "got flags $flags back");
    my @res = mem_gets($sock, "foo");
    mem_gets_is({ sock => $sock,
                  flags => $flags }, $res[0], "foo", "fooval", "got flags $flags back");

}



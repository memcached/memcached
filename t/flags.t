#!/usr/bin/env perl

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

my @fset = (0, 123, 2**16-1, 2**31);
my $stats = mem_stats($sock, "settings");
if ($stats->{client_flags_size} == 8) {
    note "extra tests for large flags";
    push(@fset, 2**32);
    push(@fset, 2**48);
}

# set foo (and should get it)
for my $flags (@fset) {
    print $sock "set foo $flags 0 6\r\nfooval\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored foo");
    mem_get_is({ sock => $sock,
                 flags => $flags }, "foo", "fooval", "got flags $flags back");
}

done_testing();

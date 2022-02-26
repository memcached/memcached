#!/usr/bin/env perl

# These command strings are always expected to be malicious and as such we
# should just hang up on them.

use strict;
use Test::More tests => 3;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my @strs = (
    "GET / HTTP/1.0",
    "PUT /asdf/asd/fasdfasdf/sadf HTTP/1.1",
    "DELETE HTTP/1.1"
);

for my $str (@strs) {
    my $server = new_memcached();
    my $sock = $server->sock;

    print $sock "$str\r\n";

    # Five seconds ought to be enough to get hung up on.
    my $oldalarmt = alarm(5);

    # Verify we can't read anything.
    my $bytesread = -1;
    eval {
        local $SIG{'ALRM'} = sub { die "timeout" };
        my $data = "";
        $bytesread = sysread($sock, $data, 24),
    };
    is($bytesread, 0, $str);

    # Restore signal stuff.
    alarm($oldalarmt);
}

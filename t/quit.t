#!/usr/bin/perl

use strict;
use Test::More tests => 1;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

{
    print $sock "quit\r\n";

    # Five seconds ought to be enough to get hung up on.
    my $oldalarmt = alarm(5);

    # Verify we can't read anything.
    my $bytesread = -1;
    eval {
        local $SIG{'ALRM'} = sub { die "timeout" };
        my $data = "";
        $bytesread = sysread($sock, $data, 24),
    };
    is($bytesread, 0, "Read after quit.");

    # Restore signal stuff.
    alarm($oldalarmt);
}

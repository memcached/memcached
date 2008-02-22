#! /usr/bin/perl
#
use warnings;
use strict;

use IO::Socket::INET;

use FindBin;

@ARGV == 1 or @ARGV == 2
    or die "Usage: $FindBin::Script HOST:PORT [COUNT]\n";

# Note that it's better to run the test over the wire, because for
# localhost the task may become CPU bound.
my $addr = $ARGV[0];
my $count = $ARGV[1] || 10_000;

my $sock = IO::Socket::INET->new(PeerAddr => $addr,
                                 Timeout  => 3);
die "$!\n" unless $sock;


# By running 'noreply' test first we also ensure there are no reply
# packets left in the network.
foreach my $noreply (1, 0) {
    use Time::HiRes qw(gettimeofday tv_interval);

    print "'noreply' is ", $noreply ? "enabled" : "disabled", ":\n";
    my $param = $noreply ? 'noreply' : '';
    my $start = [gettimeofday];
    foreach (1 .. $count) {
        print $sock "add foo 0 0 1 $param\r\n1\r\n";
        scalar<$sock> unless $noreply;
        print $sock "set foo 0 0 1 $param\r\n1\r\n";
        scalar<$sock> unless $noreply;
        print $sock "replace foo 0 0 1 $param\r\n1\r\n";
        scalar<$sock> unless $noreply;
        print $sock "append foo 0 0 1 $param\r\n1\r\n";
        scalar<$sock> unless $noreply;
        print $sock "prepend foo 0 0 1 $param\r\n1\r\n";
        scalar<$sock> unless $noreply;
        print $sock "incr foo 1 $param\r\n";
        scalar<$sock> unless $noreply;
        print $sock "decr foo 1 $param\r\n";
        scalar<$sock> unless $noreply;
        print $sock "delete foo $param\r\n";
        scalar<$sock> unless $noreply;
    }
    my $end = [gettimeofday];
    printf("update commands: %.2f secs\n\n", tv_interval($start, $end));
}

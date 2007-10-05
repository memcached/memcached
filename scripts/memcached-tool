#!/usr/bin/perl
#
# memcached-tool:
#   stats/management tool for memcached.
#
# Author:
#   Brad Fitzpatrick <brad@danga.com>
#
# License:
#   public domain.  I give up all rights to this
#   tool.  modify and copy at will.
#

use strict;
use IO::Socket::INET;

my $host = shift;
my $mode = shift || "display";
my ($from, $to);

if ($mode eq "display") {
    undef $mode if @ARGV;
} elsif ($mode eq "move") {
    $from = shift;
    $to = shift;
    undef $mode if $from < 6 || $from > 17;
    undef $mode if $to   < 6 || $to   > 17;
    print STDERR "ERROR: parameters out of range\n\n" unless $mode;
} elsif ($mode eq 'dump') {
    ;
} elsif ($mode eq 'stats') {
    ;
} else {
    undef $mode;
}

undef $mode if @ARGV;

die 
"Usage: memcached-tool <host[:port]> [mode]\n
       memcached-tool 10.0.0.5:11211 display    # shows slabs
       memcached-tool 10.0.0.5:11211            # same.  (default is display)
       memcached-tool 10.0.0.5:11211 stats      # shows general stats
       memcached-tool 10.0.0.5:11211 move 7 9   # takes 1MB slab from class #7
                                                # to class #9.

You can only move slabs around once memory is totally allocated, and only
once the target class is full.  (So you can't move from #6 to #9 and #7
to #9 at the same itme, since you'd have to wait for #9 to fill from
the first reassigned page)
" unless $host && $mode;

$host .= ":11211" unless $host =~ /:\d+/;

my $sock = IO::Socket::INET->new(PeerAddr => $host,
				 Proto    => 'tcp');
die "Couldn't connect to $host\n" unless $sock;


if ($mode eq "move") {
    my $tries = 0;
    while (1) {
	print $sock "slabs reassign $from $to\r\n";
	my $res = <$sock>;
	$res =~ s/\s+//;
	if ($res eq "DONE") {
	    print "Success.\n";
	    exit 0;
	} elsif ($res eq "CANT") {
	    print "Error: can't move from $from to $to.  Destination not yet full?  See usage docs.\n";
	    exit;
	} elsif ($res eq "BUSY") {
	    if (++$tries == 3) {
		print "Failed to move after 3 tries.  Try again later.\n";
		exit;
	    }

	    print "Page busy, retrying...\n";
	    sleep 1;
	}
    }

    exit;
}

if ($mode eq 'dump') {
    my %items;
    my $totalitems;

    print $sock "stats items\r\n";

    while (<$sock>) {
        last if /^END/;
        if (/^STAT items:(\d*):number (\d*)/) {
            $items{$1} = $2;
            $totalitems += $2;
        }
    }
    print STDERR "Dumping memcache contents\n";
    print STDERR "  Number of buckets: " . scalar(keys(%items)) . "\n";
    print STDERR "  Number of items  : $totalitems\n";

    foreach my $bucket (sort(keys(%items))) {
        print STDERR "Dumping bucket $bucket - " . $items{$bucket} . " total items\n";
        print $sock "stats cachedump $bucket $items{$bucket} 1\r\n";
        my %keyexp;
        while (<$sock>) {
            last if /^END/;
            # return format looks like this
            # ITEM foo [6 b; 1176415152 s]
            if (/^ITEM (\S+) \[.* (\d+) s\]/) {
                $keyexp{$1} = $2;
            }
        }

        foreach my $k (keys(%keyexp)) {
            my $val;
            print $sock "get $k\r\n";
            my $response = <$sock>;
            $response =~ /VALUE (\S+) (\d+) (\d+)/;
            my $flags = $2;
            my $len = $3;
            read $sock, $val , $len;
            # get the END
            $_ = <$sock>;
            $_ = <$sock>;
            print "add $k $flags $keyexp{$k} $len\r\n$val\r\n";
        }
    }
    exit;
}

if ($mode eq 'stats') {
    my %items;

    print $sock "stats\r\n";

    while (<$sock>) {
        last if /^END/;
        chomp;
        if (/^STAT\s+(\S*)\s+(.*)/) {
            $items{$1} = $2;
        }
    }
    printf ("#%-17s %5s %11s\n", $host, "Field", "Value");
    foreach my $name (sort(keys(%items))) {
      printf ("%24s %12s\n", $name, $items{$name});
      
    }
    exit;
}

# display mode:

my %items;  # class -> { number, age, chunk_size, chunks_per_page,
            #            total_pages, total_chunks, used_chunks,
            #            free_chunks, free_chunks_end }

print $sock "stats items\r\n";
while (<$sock>) {
    last if /^END/;
    if (/^STAT items:(\d+):(\w+) (\d+)/) {
	$items{$1}{$2} = $3;
    }
}

print $sock "stats slabs\r\n";
while (<$sock>) {
    last if /^END/;
    if (/^STAT (\d+):(\w+) (\d+)/) {
	$items{$1}{$2} = $3;
    }
}

print "  #  Item_Size   Max_age  1MB_pages Count   Full?\n";
foreach my $n (1..40) {
    my $it = $items{$n};
    next if (0 == $it->{total_pages});
    my $size = $it->{chunk_size} < 1024 ? "$it->{chunk_size} B " : 
	sprintf("%.1f kB", $it->{chunk_size} / 1024.0);
    my $full = $it->{free_chunks_end} == 0 ? "yes" : " no";
    printf "%3d   %8s %7d s %7d %7d %7s\n",
                        $n, $size, $it->{age}, $it->{total_pages},
                        $it->{number}, $full;
}


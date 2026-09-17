#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Data::Dumper qw/Dumper/;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

# TODO: move wait_for_ext into Memcached.pm
sub wait_for_ext {
    my $sock = shift;
    my $target = shift || 0;
    my $sum = $target + 1;
    while ($sum > $target) {
        my $s = mem_stats($sock, "items");
        $sum = 0;
        for my $key (keys %$s) {
            if ($key =~ m/items:(\d+):number/) {
                # Ignore classes which can contain extstore items
                next if $1 < 3;
                $sum += $s->{$key};
            }
        }
        sleep 1 if $sum > $target;
    }
}

sub mget_is {
    # single line values only
    my ($o, $key, $val, $msg) = @_;

    my $dval = defined $val ? "'$val'" : "<undef>";
    $msg ||= "$key == $dval";

    my $s = $o->{sock};
    my $flags = $o->{flags};
    my $eflags = $o->{eflags} || $flags;

    print $s "mg $key $flags\r\n";
    if (! defined $val) {
        my $line = scalar <$s>;
        if ($line =~ /^VA/) {
            $line .= scalar(<$s>);
        }
        Test::More::is($line, "EN\r\n", $msg);
    } else {
        my $len = length($val);
        my $body = scalar(<$s>);
        my $expected = "VA $len $eflags\r\n$val\r\n";
        if (!$body || $body =~ /^EN/) {
            Test::More::is($body, $expected, $msg);
            return;
        }
        $body .= scalar(<$s>);
        Test::More::is($body, $expected, $msg);
        return mget_res($body);
    }
    return {};
}

# parse out a response
sub mget_res {
    my $resp = shift;
    my %r = ();

    if ($resp =~ m/^VA (\d+) ([^\r]+)\r\n(.*)\r\n/gm) {
        $r{size} = $1;
        $r{flags} = $2;
        $r{val} = $3;
    } elsif ($resp =~ m/^HD\s*([^\r]+)\r\n/gm) {
        $r{flags} = $1;
        $r{hd} = 1;
    } elsif ($resp =~ m/^EN/gm) {
        # do nothing?
    } else {
        die "Unable to parse mget response: $resp";
    }

    return \%r;
}

my $ext_path = "/tmp/extstore.$$";

subtest 'metaget against extstore' => sub {
    my $server = new_memcached("-m 64 -U 0 -o ext_page_size=8,ext_wbuf_size=2,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=2,ext_recache_rate=10000,ext_max_frag=0.9,ext_path=$ext_path:64m,slab_automove=0,ext_compact_under=1,no_lru_crawler");
    my $sock = $server->sock;

    my $value;
    {
        my @chars = ("C".."Z");
        for (1 .. 20000) {
            $value .= $chars[rand @chars];
        }
    }

    my $keycount = 10;
    for (1 .. $keycount) {
        print $sock "set nfoo$_ 0 0 20000 noreply\r\n$value\r\n";
    }

    wait_for_ext($sock);
    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's20000' },
            'nfoo1', $value, "retrieved test value");
    my $stats = mem_stats($sock);
    cmp_ok($stats->{get_extstore}, '>', 0, 'one object was fetched');

    my $ovalue = $value;
    for (1 .. 4) {
        $value .= $ovalue;
    }
    # Fill to eviction.
    $keycount = 1000;
    for (1 .. $keycount) {
        print $sock "set mfoo$_ 0 0 100000 noreply\r\n$value\r\n";
        # wait to avoid memory evictions
        wait_for_ext($sock, 1) if ($_ % 250 == 0);
    }

    print $sock "mg mfoo1 s v\r\n";
    is(scalar <$sock>, "EN\r\n");
    print $sock "mg mfoo1 s v q\r\nmn\r\n";
    is(scalar <$sock>, "MN\r\n");
    $stats = mem_stats($sock);
    cmp_ok($stats->{miss_from_extstore}, '>', 0, 'at least one miss');
};

done_testing();

END {
    unlink $ext_path if $ext_path;
}

#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Socket qw(AF_INET SOCK_STREAM);
use IO::Select;
use Data::Dumper qw/Dumper/;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

# Set up some server sockets.
sub mock_server {
    my $port = shift;
    my $srv = IO::Socket->new(
        Domain => AF_INET,
        Type => SOCK_STREAM,
        Proto => 'tcp',
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        ReusePort => 1,
        Listen => 5) || die "IO::Socket: $@";
    return $srv;
}

# Put a version command down the pipe to ensure the socket is clear.
# client version commands skip the proxy code
sub check_version {
    my $ps = shift;
    print $ps "version\r\n";
    like(<$ps>, qr/VERSION /, "version received");
}

my $p_srv = new_memcached("-o proxy_config=./t/proxyinternal2.lua,slab_chunk_max=32 -t 1");
my $ps = $p_srv->sock;
$ps->autoflush(1);

subtest 'basic large item' => sub {
    my $data = 'x' x 500000;
    print $ps "set /b/beeeg 0 0 500000\r\n$data\r\n";
    is(scalar <$ps>, "STORED\r\n", "big item stored");

    print $ps "get /b/beeeg\r\n";
    is(scalar <$ps>, "VALUE /b/beeeg 0 500000\r\n", "got large response");
    is(scalar <$ps>, "$data\r\n", "got data portion back");
    is(scalar <$ps>, "END\r\n", "saw END");

    print $ps "delete /b/beeeg\r\n";
    is(scalar <$ps>, "DELETED\r\n");
    check_version($ps);
};

subtest 'basic chunked item' => sub {
    my $data = 'x' x 900000;
    print $ps "set /b/chunked 0 0 900000\r\n$data\r\n";
    is(scalar <$ps>, "STORED\r\n", "big item stored");

    print $ps "get /b/chunked\r\n";
    is(scalar <$ps>, "VALUE /b/chunked 0 900000\r\n", "got large response");
    is(scalar <$ps>, "$data\r\n", "got data portion back");
    is(scalar <$ps>, "END\r\n", "saw END");

    print $ps "delete /b/chunked\r\n";
    is(scalar <$ps>, "DELETED\r\n");
    check_version($ps);
};

subtest 'flood memory' => sub {
    # ensure we don't have a basic reference counter leak
    my $data = 'x' x 500000;
    for (1 .. 200) {
        print $ps "set /b/$_ 0 0 500000\r\n$data\r\n";
        is(scalar <$ps>, "STORED\r\n", "flood set");
    }
    for (1 .. 200) {
        print $ps "ms /b/$_ 500000 T30\r\n$data\r\n";
        is(scalar <$ps>, "HD\r\n", "flood ms");
    }

    # overwrite the same value a bunch of times.
    for (1 .. 200) {
        print $ps "ms BOOM 500000 T30\r\n$data\r\n";
        is(scalar <$ps>, "HD\r\n", "flood ms");
        # fetch to attempt to leak objects
        mem_get_is($ps, "BOOM", $data);
    }
    print $ps "md BOOM\r\n";
    like(scalar <$ps>, qr/HD|NF/, "deleted");

    check_version($ps);
};

subtest 'check stats' => sub {
    # delete things manually since we can't easily call flush_all
    for (1 .. 200) {
        print $ps "md /b/$_\r\n";
        like(scalar <$ps>, qr/HD|NF/, "deleted");
    }
    # everything else should've been pushed out of memory by the flood

    my $s = mem_stats($ps, 'slabs');
    for my $k (keys %$s) {
        if ($k =~ m/(\d+):used/) {
            is($s->{$k}, 0, "class " . $k . " is empty")
            #print STDERR $k, " => ", $s->{$k}, "\n";
        }
    }
    #print STDERR "DUMP:", Dumper($s), "\n";
};

done_testing();

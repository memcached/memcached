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

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

# Don't want to write two distinct set of tests, and extstore is a default.
if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

my $ext_path = "/tmp/proxyinternal.$$";

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

my @mocksrvs = ();
#diag "making mock servers";
for my $port (11611, 11612, 11613) {
    my $srv = mock_server($port);
    ok(defined $srv, "mock server created");
    push(@mocksrvs, $srv);
}

my $p_srv = new_memcached("-o proxy_config=./t/proxyinternal.lua,ext_item_size=500,ext_item_age=1,ext_path=$ext_path:64m,ext_max_sleep=100000");
my $ps = $p_srv->sock;
$ps->autoflush(1);

# set up server backend sockets.
# uncomment when needed. currently they get thrown out so this can hang.
#my @mbe = ();
#diag "accepting mock backends";
#for my $msrv (@mocksrvs) {
#    my $be = $msrv->accept();
#    $be->autoflush(1);
#    ok(defined $be, "mock backend created");
#    push(@mbe, $be);
#}

#diag "validating backends";
#for my $be (@mbe) {
#    like(<$be>, qr/version/, "received version command");
#    print $be "VERSION 1.0.0-mock\r\n";
#}

#diag "object too large"
{
    my $data = 'x' x 2000000;
    print $ps "set /b/toolarge 0 0 2000000\r\n$data\r\n";
    is(scalar <$ps>, "SERVER_ERROR object too large for cache\r\n", "set too large");

    print $ps "ms /b/toolarge 2000000 T30\r\n$data\r\n";
    is(scalar <$ps>, "SERVER_ERROR object too large for cache\r\n", "ms too large");
}

#diag "basic tests"
{
    print $ps "set /b/foo 0 0 2\r\nhi\r\n";
    is(scalar <$ps>, "STORED\r\n", "int set");
    print $ps "get /b/foo\r\n";
    is(scalar <$ps>, "VALUE /b/foo 0 2\r\n", "get response");
    is(scalar <$ps>, "hi\r\n", "get value");
    is(scalar <$ps>, "END\r\n", "get END");
}

#diag "fetch from extstore"
{
    my $data = 'x' x 1000;
    print $ps "set /b/ext 0 0 1000\r\n$data\r\n";
    is(scalar <$ps>, "STORED\r\n", "int set for extstore");
    sleep 3; # TODO: import wait_for_ext

    print $ps "get /b/ext\r\n";
    is(scalar <$ps>, "VALUE /b/ext 0 1000\r\n", "get response from extstore");
    is(scalar <$ps>, "$data\r\n", "got data from extstore");
    is(scalar <$ps>, "END\r\n", "get END");
}

#diag "flood memory"
{
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
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

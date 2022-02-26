#!/usr/bin/env perl
# Test for adding connection id to the output when watching fetchers
# and mutations.
# Note that this test relies on the order of connection establishments. This
# could be improved if there's a way for a client to retrieve its connection id.
use strict;
use warnings;
use Socket qw/SO_RCVBUF/;

use Test::More tests => 4;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached('-m 60 -o watcher_logbuf_size=8');
my $client_first = $server->sock;

my $stats;

# get the first client's connection id
print $client_first "stats conns\r\n";
while (<$client_first>) {
    last if /^(\.|END)/;
    $stats = $_;
}
my $cfd_first  =(split(':', $stats))[0];
$cfd_first =~ s/[^0-9]//g;

# start watching fetchers and mutations
my $watcher = $server->new_sock;
print $watcher "watch fetchers mutations\n";
my $res = <$watcher>;
is($res, "OK\r\n", "watching enabled for fetchers and mutations");

# first client does a set, which will result in a get and a set
print $client_first "set foo 0 0 5 noreply\r\nhello\r\n";

# ensure client's connection id is correct
$res = <$watcher>;
print $res;
like($res, qr/ts=\d+\.\d+\ gid=\d+ type=item_get key=foo status=not_found clsid=\d+ cfd=$cfd_first/,
    "Saw a miss with the connection id $cfd_first");
$res = <$watcher>;
print $res;
like($res, qr/ts=\d+\.\d+\ gid=\d+ type=item_store key=foo status=stored cmd=set ttl=\d+ clsid=\d+ cfd=$cfd_first/,
    "Saw a set with the connection id $cfd_first");

# get the second client's connection id
my $client_second = $server->new_sock;
print $client_second "stats conns\r\n";
while (<$client_second>) {
    last if /^(\.|END)/;
    $stats = $_;
}
my $cfd_second  =(split(':', $stats))[0];
$cfd_second =~ s/[^0-9]//g;

# second client does a get
print $client_second "get foo\r\n";

# now we should see second client's connection id
$res = <$watcher>;
print $res;
like($res, qr/ts=\d+\.\d+\ gid=\d+ type=item_get key=foo status=found clsid=\d+ cfd=$cfd_second/,
    "Saw a get with the connection id $cfd_second");


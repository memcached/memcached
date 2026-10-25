#!/usr/bin/env perl

# Config reloads that fail must leave the proxy running on its previous
# configuration, and must not break later reloads.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;

my $modefile = "/tmp/proxyreloadfail.lua";

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

sub write_mode {
    my $mode = shift;
    open(my $fh, "> $modefile") or die "Couldn't overwrite $modefile: $!";
    print $fh $mode;
    close($fh);
}

write_mode('return "first"');
my $p_srv = new_memcached('-o proxy_config=./t/proxyreloadfail.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

my $watcher = $p_srv->new_sock;
print $watcher "watch proxyevents\n";
is(<$watcher>, "OK\r\n", "watcher enabled");

sub reload_status {
    my $status = shift;
    $p_srv->reload();
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=$status/, "reload $status");
}

sub check_route {
    my $mode = shift;
    print $ps "mg foo\r\n";
    is(scalar <$ps>, "SERVER_ERROR $mode\r\n", "routed by the '$mode' config");
}

check_route("first");

subtest 'failed worker reload, then a good reload' => sub {
    write_mode('return "routes_error"');
    reload_status("failed");

    # the next reload used to find the failed reload's leftovers on the
    # config thread's lua stack.
    write_mode('return "second"');
    reload_status("done");
    check_route("second");

    write_mode('return "third"');
    reload_status("done");
    check_route("third");
};

done_testing();

END {
    unlink $modefile;
}

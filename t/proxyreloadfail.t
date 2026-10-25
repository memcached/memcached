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
my $mainfile = "/tmp/proxyreloadfail-main.lua";

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

subtest 'error in mcp_config_pools' => sub {
    write_mode('return "pools_error"');
    reload_status("failed");
    check_route("third");

    write_mode('return "fourth"');
    reload_status("done");
    check_route("fourth");
};

subtest 'error while loading the config file' => sub {
    # the config file runs the mode file, so this raises an error while
    # the config file itself is being executed.
    write_mode('error("config load failed on purpose")');
    reload_status("failed");
    check_route("fourth");

    write_mode('return "fifth"');
    reload_status("done");
    check_route("fifth");
};

subtest 'syntax error in the config file' => sub {
    # the config file itself has to change here, so use a copy of it.
    open(my $in, "<", "./t/proxyreloadfail.lua") or die "Couldn't open config: $!";
    my $good = do { local $/; <$in> };
    close($in);
    open(my $fh, "> $mainfile") or die "Couldn't write $mainfile: $!";
    print $fh $good;
    close($fh);

    write_mode('return "sixth"');
    my $srv = new_memcached("-o proxy_config=$mainfile -t 1");
    my $s = $srv->sock;
    $s->autoflush(1);
    my $w = $srv->new_sock;
    print $w "watch proxyevents\n";
    is(<$w>, "OK\r\n", "watcher enabled");

    open($fh, ">> $mainfile") or die "Couldn't append to $mainfile: $!";
    print $fh "\nfunction broken(\n";
    close($fh);
    $srv->reload();
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=failed/, "reload failed");
    print $s "mg foo\r\n";
    is(scalar <$s>, "SERVER_ERROR sixth\r\n", "still routed by the old config");

    open($fh, "> $mainfile") or die "Couldn't write $mainfile: $!";
    print $fh $good;
    close($fh);
    write_mode('return "seventh"');
    $srv->reload();
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=start/, "reload started");
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_conf status=done/, "reload completed");
    print $s "mg foo\r\n";
    is(scalar <$s>, "SERVER_ERROR seventh\r\n", "routed by the fixed config");
    $srv->stop();
};

done_testing();

END {
    unlink $modefile;
    unlink $mainfile;
}

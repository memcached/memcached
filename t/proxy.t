#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;

# TODO: to module?
# or "gettimedrun" etc
use Cwd;
my $builddir = getcwd;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

# TODO: the lua file has hardcoded ports. any way to make this dynamic?
# TODO: once basic tests are done, actually split out the instances rather
# than the shared backend; validate keys go where they should be going.

# FIXME: this listend on unix socket still. either need a manual runner or a
# fix upstream.
my @srv = ();
for (2 .. 6) {
    my $srv = run_server("-p 1121$_", 11210 + $_);
    push(@srv, $srv);
}
#my $sock = $srv->sock;

my $p_srv = new_memcached('-o proxy_config=./t/startfile.lua -l 127.0.0.1', 11211);
my $p_sock = $p_srv->sock;

# hack to help me use T_MEMD_USE_DAEMON for proxy.
#print STDERR "Sleeping\n";
#sleep 900;

# cmds to test:
# - noreply for main text commands?
# meta:
# me
# mn
# mg
# ms
# md
# ma
# - noreply?
# stats
# pass-thru?

# incr/decr
{
    print $p_sock "set /foo/num 0 0 1\r\n1\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "stored num");
    mem_get_is($p_sock, "/foo/num", 1, "stored 1");

    print $p_sock "incr /foo/num 1\r\n";
    is(scalar <$p_sock>, "2\r\n", "+ 1 = 2");
    mem_get_is($p_sock, "/foo/num", 2);

    print $p_sock "incr /foo/num 8\r\n";
    is(scalar <$p_sock>, "10\r\n", "+ 8 = 10");
    mem_get_is($p_sock, "/foo/num", 10);

    print $p_sock "decr /foo/num 1\r\n";
    is(scalar <$p_sock>, "9\r\n", "- 1 = 9");

    print $p_sock "decr /foo/num 9\r\n";
    is(scalar <$p_sock>, "0\r\n", "- 9 = 0");

    print $p_sock "decr /foo/num 5\r\n";
    is(scalar <$p_sock>, "0\r\n", "- 5 = 0");
}

# gat
{
    # cache miss
    print $p_sock "gat 10 /foo/foo1\r\n";
    is(scalar <$p_sock>, "END\r\n", "cache miss");

    # set /foo/foo1 and /foo/foo2 (and should get it)
    print $p_sock "set /foo/foo1 0 2 7\r\nfooval1\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "stored foo");

    print $p_sock "set /foo/foo2 0 2 7\r\nfooval2\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "stored /foo/foo2");

    # get and touch it with cas
    print $p_sock "gats 10 /foo/foo1 /foo/foo2\r\n";
    like(scalar <$p_sock>, qr/VALUE \/foo\/foo1 0 7 (\d+)\r\n/, "get and touch foo1 with cas regexp success");
    is(scalar <$p_sock>, "fooval1\r\n","value");
    like(scalar <$p_sock>, qr/VALUE \/foo\/foo2 0 7 (\d+)\r\n/, "get and touch foo2 with cas regexp success");
    is(scalar <$p_sock>, "fooval2\r\n","value");
    is(scalar <$p_sock>, "END\r\n", "end");

    # get and touch it without cas
    print $p_sock "gat 10 /foo/foo1 /foo/foo2\r\n";
    like(scalar <$p_sock>, qr/VALUE \/foo\/foo1 0 7\r\n/, "get and touch foo1 without cas regexp success");
    is(scalar <$p_sock>, "fooval1\r\n","value");
    like(scalar <$p_sock>, qr/VALUE \/foo\/foo2 0 7\r\n/, "get and touch foo2 without cas regexp success");
    is(scalar <$p_sock>, "fooval2\r\n","value");
    is(scalar <$p_sock>, "END\r\n", "end");
}

# gets/cas
{
    print $p_sock "add /foo/moo 0 0 6\r\nmooval\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "stored mooval");
    mem_get_is($p_sock, "/foo/moo", "mooval");

    # check-and-set (cas) failure case, try to set value with incorrect cas unique val
    print $p_sock "cas /foo/moo 0 0 6 0\r\nMOOVAL\r\n";
    is(scalar <$p_sock>, "EXISTS\r\n", "check and set with invalid id");

    # test "gets", grab unique ID
    print $p_sock "gets /foo/moo\r\n";
    # VALUE moo 0 6 3084947704
    #
    my @retvals = split(/ /, scalar <$p_sock>);
    my $data = scalar <$p_sock>; # grab data
    my $dot  = scalar <$p_sock>; # grab dot on line by itself
    is($retvals[0], "VALUE", "get value using 'gets'");
    my $unique_id = $retvals[4];
    # clean off \r\n
    $unique_id =~ s/\r\n$//;
    ok($unique_id =~ /^\d+$/, "unique ID '$unique_id' is an integer");
    # now test that we can store moo with the correct unique id
    print $p_sock "cas /foo/moo 0 0 6 $unique_id\r\nMOOVAL\r\n";
    is(scalar <$p_sock>, "STORED\r\n");
    mem_get_is($p_sock, "/foo/moo", "MOOVAL");
}

# touch
{
    print $p_sock "set /foo/t 0 2 6\r\nfooval\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "stored foo");
    mem_get_is($p_sock, "/foo/t", "fooval");

    # touch it
    print $p_sock "touch /foo/t 10\r\n";
    is(scalar <$p_sock>, "TOUCHED\r\n", "touched foo");

    # don't need to sleep/validate the touch worked. We're testing the
    # protocol, not the functionality.
}

# command endings
# NOTE: memcached always allowed [\r]\n for single command lines, but payloads
# (set/etc) require exactly \r\n as termination.
# doc/protocol.txt has always specified \r\n for command/response.
# Proxy is more strict than normal server in this case.
{
    my $s = $srv[0]->sock;
    print $s "version\n";
    like(<$s>, qr/VERSION/, "direct server version cmd with just newline");
    print $p_sock "version\n";
    like(<$p_sock>, qr/SERVER_ERROR/, "proxy version cmd with just newline");
    print $p_sock "version\r\n";
    like(<$p_sock>, qr/VERSION/, "proxy version cmd with full CRLF");
}

# set through proxy.
{
    print $p_sock "set /foo/z 0 0 5\r\nhello\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "stored test value through proxy");
    # ensure it's fetchable.
    mem_get_is($p_sock, "/foo/z", "hello");
    # delete it.
    print $p_sock "delete /foo/z\r\n";
    is(scalar <$p_sock>, "DELETED\r\n", "removed test value");
    # ensure it's deleted.
    mem_get_is($p_sock, "/foo/z", undef);
}

# test add.
{
    print $p_sock "add /foo/a 0 0 3\r\nmoo\r\n";
    is(scalar <$p_sock>, "STORED\r\n", "add test value through proxy");
    # ensure it's fetchable
    mem_get_is($p_sock, "/foo/a", "moo");
    # check re-adding fails.
    print $p_sock "add /foo/a 0 0 3\r\ngoo\r\n";
    is(scalar <$p_sock>, "NOT_STORED\r\n", "re-add fails");
    # ensure we still hae the old value
    mem_get_is($p_sock, "/foo/a", "moo");
}

# pipelined set.
{
    my $str = "set /foo/k 0 0 5\r\nhello\r\n";
    print $p_sock "$str$str$str$str$str";
    is(scalar <$p_sock>, "STORED\r\n", "stored test value through proxy");
    is(scalar <$p_sock>, "STORED\r\n", "stored test value through proxy");
    is(scalar <$p_sock>, "STORED\r\n", "stored test value through proxy");
    is(scalar <$p_sock>, "STORED\r\n", "stored test value through proxy");
    is(scalar <$p_sock>, "STORED\r\n", "stored test value through proxy");
}

# Load some keys through proxy.
my $bdata = 'x' x 256000;
{
    for (1..20) {
        print $p_sock "set /foo/a$_ 0 0 2\r\nhi\r\n";
        is(scalar <$p_sock>, "STORED\r\n", "stored test value");
        print $p_sock "set /bar/b$_ 0 0 2\r\nhi\r\n";
        is(scalar <$p_sock>, "STORED\r\n", "stored test value");
    }

    # load a couple larger values
    for (1..4) {
        print $p_sock "set /foo/big$_ 0 0 256000\r\n$bdata\r\n";
        is(scalar <$p_sock>, "STORED\r\n", "stored big value");
    }
    diag "set large values";
}

# fetch through proxy.
{
    for (1..20) {
        mem_get_is($p_sock, "/foo/a$_", "hi");
    }
    diag "fetched small values";
    mem_get_is($p_sock, "/foo/big1", $bdata);
    diag "fetched big value";
}

sub run_server {
    my ($args, $port) = @_;

    my $exe = get_memcached_exe();

    my $childpid = fork();

    my $root = '';
    $root = "-u root" if ($< == 0);

    # test build requires more privileges
    $args .= " -o relaxed_privileges";

    my $cmd = "$builddir/timedrun 120 $exe $root $args";

    unless($childpid) {
        exec $cmd;
        exit; # NOTREACHED
    }

    for (1..20) {
        my $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
        if ($conn) {
            return Memcached::Handle->new(pid  => $childpid,
                conn => $conn,
                host => "127.0.0.1",
                port => $port);
        }
        select undef, undef, undef, 0.10;
    }
    croak "Failed to start server.";
}

done_testing();

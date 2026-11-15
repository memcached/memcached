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

# Put a version command down the pipe to ensure the socket is clear.
# client version commands skip the proxy code
sub check_version {
    my $ps = shift;
    print $ps "version\r\n";
    like(<$ps>, qr/VERSION /, "version received");
}

my $t = Memcached::ProxyTest->new(servers => []);

my $p_srv = new_memcached("-R 500 -o proxy_config=./t/proxyinternal.lua,ext_item_size=500,ext_item_age=1,ext_path=$ext_path:64m,ext_max_sleep=100000 -t 1");
my $ps = $p_srv->sock;
$ps->autoflush(1);

$t->set_c($ps);

{
    test_res();
    test_basics();
    test_fetch_extstore();
    test_pipe_extstore();
    test_etc();
}

# ensure the result objects still function for internal RES.
# NOTE: could cuddle the mode with P or L flags but I wanted to seed the item
# for each individual test.
sub test_res {
    subtest 'response/hit' => sub {
        $t->c_send("mg response/hit v t\r\n");
        $t->c_recv("SERVER_ERROR res:hit = false\r\n");

        $t->c_send("ms response/hit 2\r\nhi\r\n");
        $t->c_recv("HD\r\n", "seeding hit response");

        $t->c_send("mg response/hit v t\r\n");
        $t->c_recv("SERVER_ERROR res:hit = true\r\n");

        $t->clear();
    };

    # NOTE: if this test fails it may be because MCMC_CODE numbers changed
    subtest 'response/code' => sub {
        $t->c_send("mg response/code v t\r\n");
        $t->c_recv("SERVER_ERROR res:code = 17\r\n");

        $t->c_send("ms response/code 2\r\nhi\r\n");
        $t->c_recv("HD\r\n", "seeding response");

        $t->c_send("mg response/code v t\r\n");
        $t->c_recv("SERVER_ERROR res:code = 15\r\n");

        $t->clear();
    };

    subtest 'response/line' => sub {
        $t->c_send("mg response/line v t\r\n");
        $t->c_recv("SERVER_ERROR res:line = nil\r\n");

        $t->c_send("ms response/line 2\r\nhi\r\n");
        $t->c_recv("HD\r\n", "seeding response");

        $t->c_send("mg response/line v t s h\r\n");
        $t->c_recv("SERVER_ERROR res:line = \"t-1 s2 h0\"\r\n");

        $t->clear();
    };

    subtest 'response/line' => sub {
        $t->c_send("mg response/vlen v t\r\n");
        $t->c_recv("SERVER_ERROR res:vlen = 0\r\n");

        $t->c_send("ms response/vlen 5\r\nhello\r\n");
        $t->c_recv("HD\r\n", "seeding response");

        $t->c_send("mg response/vlen v t\r\n");
        $t->c_recv("SERVER_ERROR res:vlen = 5\r\n");

        $t->clear();
    };

}

sub test_basics {
    subtest 'ms/mg' => sub {
        $t->c_send("ms /b/a 2\r\nhi\r\n");
        $t->c_recv("HD\r\n", "bare ms command works");

        $t->c_send("ms /b/a 2 T100\r\nhi\r\n");
        $t->c_recv("HD\r\n", "ms with a TTL");

        $t->c_send("mg /b/a t\r\n");
        isnt(scalar <$ps>, "HD t-1\r\n");

        $t->clear();
    };

    note "ascii multiget";
    {
        # First test all miss.
        my @keys = ();
        for (0 .. 50) {
            push(@keys, "/b/" . $_);
        }
        print $ps "get ", join(' ', @keys), "\r\n";
        is(scalar <$ps>, "END\r\n", "all misses from multiget");
        # No extra END's after the solitary one.
        check_version($ps);

        for (@keys) {
            print $ps "set $_ 0 0 2\r\nhi\r\n";
            is(scalar <$ps>, "STORED\r\n", "successful set");
        }
        check_version($ps);
        print $ps "get ", join(' ', @keys), "\r\n";
        for (@keys) {
            is(scalar <$ps>, "VALUE $_ 0 2\r\n", "resline matches");
            is(scalar <$ps>, "hi\r\n", "value matches");
        }
        is(scalar <$ps>, "END\r\n", "final END from multiget");
        check_version($ps);
    }

    subtest 'ascii get basics' => sub {
        # Ensure all of that END removal we do in multiget doesn't apply to
        # non-multiget get mode.
        $t->c_send("get /b/miss\r\n");
        $t->c_recv("END\r\n", "basic miss");
        $t->c_send("get /sub/miss\r\n");
        $t->c_recv("END\r\n", "basic subrctx miss");

        $t->c_send("set /b/ttl 0 0 2\r\ntt\r\n");
        $t->c_recv("STORED\r\n");

        $t->c_send("mg /b/ttl t\r\n");
        $t->c_recv("HD t-1\r\n");

        $t->c_send("gat 100 /b/ttl\r\n");
        $t->c_recv("VALUE /b/ttl 0 2\r\n");
        $t->c_recv("tt\r\n");
        $t->c_recv("END\r\n");

        $t->c_send("mg /b/ttl t\r\n");
        isnt(scalar <$ps>, "HD t-1\r\n");

        $t->clear();
    };

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
        print $ps "set /sub/foo 0 0 2\r\nhi\r\n";
        is(scalar <$ps>, "STORED\r\n", "int set");

        print $ps "get /b/foo\r\n";
        is(scalar <$ps>, "VALUE /b/foo 0 2\r\n", "get response");
        is(scalar <$ps>, "hi\r\n", "get value");
        is(scalar <$ps>, "END\r\n", "get END");

        print $ps "get /sub/foo\r\n";
        is(scalar <$ps>, "VALUE /sub/foo 0 2\r\n", "get response");
        is(scalar <$ps>, "hi\r\n", "get value");
        is(scalar <$ps>, "END\r\n", "get END");
        check_version($ps);
    }

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

    subtest 'meta quiet mode' => sub {
        $t->c_send("mg response/quiet v t q\r\nmn\r\n");
        $t->c_recv("MN\r\n", "got MN instead of HD");

        $t->c_send("mg response/quiet v t q O1\r\n");
        $t->c_send("mg response/quiet v t O2\r\n");
        $t->c_send("mg response/quiet v t q O3\r\n");
        $t->c_send("mn\r\n");

        $t->c_recv("EN O2\r\n", "Got miss response from sandwiched non-quiet mg");
        $t->c_recv("MN\r\n", "saw MN response");

        $t->c_send("ms response/quiet 2 q\r\nhi\r\n");
        $t->c_send("mn\r\n");
        $t->c_recv("MN\r\n", "saw MN instead of HD from ms");

        $t->c_send("mg response/quiet v t q O4\r\n");
        $t->c_recv("VA 2 t-1 O4\r\n", "got result back from quiet mg");
        $t->c_recv("hi\r\n", "got value back from quiet mg");

        $t->c_send("mg response/quiet t q O4\r\n");
        $t->c_recv("HD t-1 O4\r\n", "got non-value response from quiet get");

        $t->c_send("ma response/counter N0 J1 q\r\n");
        $t->c_send("mn\r\n");
        $t->c_recv("MN\r\n", "got MN instead of ma response");

        $t->clear();
    };

    subtest 'noreply mode' => sub {
        $t->c_send("set response/quiet1 0 0 2 noreply\r\nhi\r\n");
        $t->c_send("set response/quiet2 0 0 2 noreply\r\nhi\r\n");
        $t->c_send("set response/quiet3 0 0 2 noreply\r\nhi\r\n");

        $t->clear();
    };
}

sub test_fetch_extstore {
    subtest 'fetch from extstore' => sub {
        my $data = 'x' x 1000;
        print $ps "set /b/ext 0 0 1000\r\n$data\r\n";
        is(scalar <$ps>, "STORED\r\n", "int set for extstore");

        print $ps "set /sub/ext 0 0 1000\r\n$data\r\n";
        is(scalar <$ps>, "STORED\r\n", "int set for subrctx extstore");

        wait_ext_flush($ps);

        print $ps "get /b/ext\r\n";
        is(scalar <$ps>, "VALUE /b/ext 0 1000\r\n", "get response from extstore");
        is(scalar <$ps>, "$data\r\n", "got data from extstore");
        is(scalar <$ps>, "END\r\n", "get END");

        print $ps "get /sub/ext\r\n";
        is(scalar <$ps>, "VALUE /sub/ext 0 1000\r\n", "get response from subrctx extstore");
        is(scalar <$ps>, "$data\r\n", "got data from extstore");
        is(scalar <$ps>, "END\r\n", "get END");
    };
}

sub test_pipe_extstore {
    subtest 'pipe fetch from extstore' => sub {
        my $size = 1000;
        my $fsize = $size + 5;
        my $data = 'x' x $size;
        my $cnt = 300;
        for (1 ..$cnt) {
            printf $ps "ms /b/ext%d $fsize\r\n%s%05d\r\n", $_, $data, $_;
            is(scalar <$ps>, "HD\r\n", "set for extstore");
        }
        wait_ext_flush($ps);

        my $piped = '';
        for (1 .. $cnt) {
            $piped .= "mg /b/ext$_ k v\r\n";
        }
        print $ps $piped;

        for (1 .. $cnt) {
            is(scalar <$ps>, "VA $fsize k/b/ext$_\r\n", "expected result line from pipe: $_");
            is(scalar <$ps>, sprintf("%s%05d\r\n", $data, $_), "expected value");
        }
    };
}

sub test_etc {
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
    };

    subtest 'watch deletions' => sub {
        my $watcher = $p_srv->new_sock;
        print $watcher "watch deletions\n";
        is(<$watcher>, "OK\r\n", "deletions watcher enabled");

        # verify watcher for delete
        print $ps "set vfoo 0 0 4\r\nvbar\r\n";
        is(<$ps>, "STORED\r\n", "stored the key");

        print $ps "delete vfoo\r\n";
        is(<$ps>, "DELETED\r\n", "key was deleted");

        like(<$watcher>, qr/ts=\d+\.\d+\ gid=\d+ type=deleted key=vfoo cmd=delete .+ size=4/,
            "delete command logged with correct size");

        # verify watcher for md
        print $ps "set vfoo 0 0 4\r\nvbar\r\n";
        is(<$ps>, "STORED\r\n", "stored the key");

        print $ps "md vfoo\r\n";
        is(<$ps>, "HD\r\n", "key was deleted");

        like(<$watcher>, qr/ts=\d+\.\d+\ gid=\d+ type=deleted key=vfoo cmd=md .+ size=4/,
            "meta-delete command logged with correct size");
    };

    subtest 'log' => sub {
        my $watcher = $p_srv->new_sock;
        print $watcher "watch proxyreqs\n";
        is(<$watcher>, "OK\r\n", "watcher enabled");

        print $ps "mg log v\r\n";
        is(scalar <$ps>, "EN\r\n", "miss received");
        like(<$watcher>, qr/detail=testing/, "got log line");
    };
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

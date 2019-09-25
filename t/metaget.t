#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

# command syntax:
# mget [key] [flags] [tokens]\r\n
# response:
# VALUE [key] [flags] [tokens]\r\n
# data\r\n
# END\r\n
#
# flags:
# - s: item size
# - v: return item value
# - c: return item cas
# - t: return item TTL remaining (-1 for unlimited)
# - f: client flags
# - l: last access time
# - h: whether item has been hit before
# - o: opaque to copy back.
# - q: noreply semantics. TODO: tests.
# - u: don't bump the item (TODO: test via 'h' flag)
# updaters:
# - N (token): vivify on miss, takes TTL as a argument
# - R (token): if token is less than item TTL win for recache
# - T (token): update remaining TTL
# FIXME: do I need a "if stale and no token sent, flip" explicit flag?
# extra response flags:
# - W: client has "won" the token
# - X: object is stale
# - Z: object has sent a winning token
#
# mset [key] [flags] [tokens]\r\n
# value\r\n
# response:
# STORED, NOT_STORED, etc
# FIXME: STORED [key] [tokens] ?
#
# flags:
# - q: noreply
# - F (token): set client flags
# - C (token): compare CAS value
# - S (token): item size
# - T (token): TTL
# - I: invalid. set-to-invalid if CAS is older than it should be.
# - E: add if not exists (influences other options)
# - A: append (exclusive)
# - P: prepend (exclusive)
# - L: replace (exclusive)
# - incr/decr? pushing it, I guess.
#
# mdelete [key] [flags] [tokens]\r\n
# response:
# FIXME
# flags:
# - q: noreply
# - T (token): updates TTL
# - C (token): compare CAS value
# - I: invalidate. mark as stale, bumps CAS.

# metaget tests

# basic test
# - raw mget
# - raw mget miss
# - raw mget bad key

{
    print $sock "set foo 0 0 2\r\nhi\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored test value");

    print $sock "mget none\r\n";
    is(scalar <$sock>, "END\r\n", "raw mget miss");

    print $sock "mget foo\r\n";
    like(scalar <$sock>, qr/^META foo /, "raw mget result");
    # bleed the END off the socket.
    my $dud = scalar <$sock>;
}

# mget with arguments
# - set some specific TTL and get it back (within reason)
# - get cas
# - autovivify and bit-win

{
    print $sock "set foo2 0 90 2\r\nho\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored test value");

    mget_is({ sock => $sock,
              flags => 'sv',
              etokens => [2] },
            'foo2', 'ho', "retrieved test value");

    my $res = mget($sock, 'foo2', 'stv');
}

# lease-test, use two sockets? one socket should be fine, actually.
# - get a win on autovivify
# - get a loss on the same command
# - have a set/cas fail
# - have a cas succeed
# - repeat for "triggered on TTL"
# - test just modifying the TTL (touch)
# - test fetching without value
{
    my $res = mget($sock, 'needwin', 'scvNt 30');
    like($res->{flags}, qr/scvNt/, "got main flags back");
    like($res->{flags}, qr/W/, "got a win result");
    unlike($res->{flags}, qr/Z/, "no token already sent warning");

    # asked for size and TTL. size should be 0, TTL should be > 0 and < 30
    is($res->{tokens}->[0], 0, "got zero size: autovivified response");
    my $ttl = $res->{tokens}->[1];
    ok($ttl > 0 && $ttl <= 30, "auto TTL is within requested window");

    # try to fail this time.
    {
        my $res = mget($sock, 'needwin', 'stcvN 30');
        ok(keys %$res, "got a non-empty response");
        unlike($res->{flags}, qr/W/, "not a win result");
        like($res->{flags}, qr/Z/, "object already sent win result");
    }

    # set back with the wrong CAS
    print $sock "mset needwin CST 5000 2 120\r\nnu\r\n";
    like(scalar <$sock>, qr/^EXISTS/, "failed to SET: CAS didn't match");

    # again, but succeed.
    # TODO: the actual CAS command should work here too?
    my $cas = $res->{tokens}->[1];
    print $sock "mset needwin CST $cas 2 120\r\nmu\r\n";
    like(scalar <$sock>, qr/^STORED/, "SET: CAS matched");

    # now we repeat the original mget, but the data should be different.
    $res = mget($sock, 'needwin', 'stcvN 30');
    ok(keys %$res, "not a miss");
    like($res->{flags}, qr/stcvN/, "got main flags back");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    is($res->{key}, 'needwin', "key matches");
    $ttl = $res->{tokens}->[1];
    ok($ttl > 100 && $ttl <= 120, "TTL is within requested window: $ttl");
    is($res->{val}, "mu", "value matches");

    # now we do the whole routine again, but for "triggered on TTL being low"
    # TTL was set to 120 just now, so anything lower than this should trigger.
    $res = mget($sock, 'needwin', 'stcvNR 30 130');
    like($res->{flags}, qr/stcvNR/, "got main flags back");
    like($res->{flags}, qr/W/, "got a win result");
    unlike($res->{flags}, qr/Z/, "no token already sent warning");
    is($res->{key}, 'needwin', "key matches");
    is($res->{val}, "mu", "value matches");

    # try to fail this time.
    {
        my $res = mget($sock, 'needwin', 'stcvNR 30 130');
        ok(keys %$res, "got a non-empty response");
        unlike($res->{flags}, qr/W/, "not a win result");
        like($res->{flags}, qr/Z/, "object already sent win result");
        is($res->{key}, 'needwin', "key matches");
        is($res->{val}, "mu", "value matches");
    }

    # again, but succeed.
    $cas = $res->{tokens}->[2];
    print $sock "mset needwin CST $cas 4 300\r\nzuuu\r\n";
    like(scalar <$sock>, qr/^STORED/, "SET: CAS matched");

    # now we repeat the original mget, but the data should be different.
    $res = mget($sock, 'needwin', 'stcvN 30');
    ok(keys %$res, "not a miss");
    like($res->{flags}, qr/stcvN/, "got main flags back");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    is($res->{key}, 'needwin', "key matches");
    $ttl = $res->{tokens}->[1];
    ok($ttl > 250 && $ttl <= 300, "TTL is within requested window");
    ok($res->{tokens}->[0] == 4, "Size returned correctly");
    is($res->{val}, "zuuu", "value matches: " . $res->{val});

}

# test get-and-touch mode
{
    # Set key with lower initial TTL.
    print $sock "mset gatkey ST 4 100\r\nooom\r\n";
    like(scalar <$sock>, qr/^STORED/, "set gatkey");

    # Coolish side feature and/or bringer of bugs: 't' before 'T' gives TTL
    # before adjustment. 'T' before 't' gives TTL after adjustment.
    # Here we want 'T' before 't' to ensure we did adjust the value.
    my $res = mget($sock, 'gatkey', 'svTt 300');
    ok(keys %$res, "not a miss");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    is($res->{key}, 'gatkey', "key matches");
    my $ttl = $res->{tokens}->[1];
    ok($ttl > 280 && $ttl <= 300, "TTL is within requested window: $ttl");
}

# test no-value mode
{
    # Set key with lower initial TTL.
    print $sock "mset hidevalue ST 4 100\r\nhide\r\n";
    like(scalar <$sock>, qr/^STORED/, "set hidevalue");

    my $res = mget($sock, 'hidevalue', 'st');
    ok(keys %$res, "not a miss");
    is($res->{val}, '', "no value returned");

    $res = mget($sock, 'hidevalue', 'stv');
    ok(keys %$res, "not a miss");
    is($res->{val}, 'hide', "real value returned");

}

# test hit-before? flag
{
    print $sock "mset hitflag ST 3 100\r\nhit\r\n";
    like(scalar <$sock>, qr/^STORED/, "set hitflag");

    my $res = mget($sock, 'hitflag', 'sth');
    ok(keys %$res, "not a miss");
    is($res->{tokens}->[2], 0, "not been hit before");

    $res = mget($sock, 'hitflag', 'sth');
    ok(keys %$res, "not a miss");
    is($res->{tokens}->[2], 1, "been hit before");
}

# test last-access time
{
    print $sock "mset la_test ST 2 100\r\nla\r\n";
    like(scalar <$sock>, qr/^STORED/, "set la_test");
    sleep 2;

    my $res = mget($sock, 'la_test', 'stl');
    ok(keys %$res, "not a miss");
    print STDERR "Last access is: ", $res->{tokens}->[2], "\n";
    isnt($res->{tokens}->[2], 0, "been over a second since most recently accessed");

    # TODO: Can't test re-accessing since it requires a long wait right now.
    # I want to adjust the LA time accuracy in a deliberate change.
}

# high level tests:
# - mget + mset with serve-stale
# - set a value
# - mget it back. should be no XZW tokens
# - invalidate via mdelete and mget/revalidate with mset
#   - remember failure scenarios!
#     - TTL timed out?
#     - CAS too high?
#   - also test re-setting as stale (CAS is below requested)
#     - this should probably be conditional.

{
    diag "starting serve stale with mdelete";
    my ($ttl, $cas, $res);
    print $sock "set toinv 0 0 3\r\nmoo\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored key 'toinv'");

    $res = mget($sock, 'toinv', 'sv');
    unlike($res->{flags}, qr/[XWZ]/, "no extra flags");

    # Lets mark the sucker as invalid, and drop its TTL to 30s
    diag "running mdelete";
    print $sock "mdelete toinv IT 30\r\n";
    like(scalar <$sock>, qr/^DELETED/, "mdelete'd key");

    # TODO: decide on if we need an explicit flag for "if I fetched a stale
    # value, does winning matter?
    # I think it's probably fine. clients can always ignore the win, or we can
    # add an option later to "don't try to revalidate if stale", perhaps.
    $res = mget($sock, 'toinv', 'stcv');
    ok(keys %$res, "not a miss");
    like($res->{flags}, qr/stcv/, "got main flags back");
    like($res->{flags}, qr/W/, "won the recache");
    like($res->{flags}, qr/X/, "item is marked stale");
    is($res->{key}, 'toinv', "key matches");
    $ttl = $res->{tokens}->[1];
    ok($ttl > 0 && $ttl <= 30, "TTL is within requested window");
    ok($res->{tokens}->[0] == 3, "Size returned correctly");
    is($res->{val}, "moo", "value matches");

    diag "trying to fail then stale set via mset";
    print $sock "mset toinv STC 1 90 0\r\nf\r\n";
    like(scalar <$sock>, qr/^EXISTS/, "failed to SET: low CAS didn't match");

    print $sock "mset toinv SITC 1 90 0\r\nf\r\n";
    like(scalar <$sock>, qr/^STORED/, "SET an invalid/stale item");

    diag "confirm item still stale, and TTL wasn't raised.";
    $res = mget($sock, 'toinv', 'stcv');
    like($res->{flags}, qr/X/, "item is marked stale");
    like($res->{flags}, qr/Z/, "win token already sent");
    unlike($res->{flags}, qr/W/, "didn't win: token already sent");
    $ttl = $res->{tokens}->[1];
    ok($ttl > 0 && $ttl <= 30, "TTL wasn't modified");

    # TODO: CAS too high?

    diag "do valid mset";
    $cas = $res->{tokens}->[2];
    print $sock "mset toinv STC 1 90 $cas\r\ng\r\n";
    like(scalar <$sock>, qr/^STORED/, "SET over the stale item");

    $res = mget($sock, 'toinv', 'stcv');
    ok(keys %$res, "not a miss");
    unlike($res->{flags}, qr/[WXZ]/, "no stale, win, or tokens");

    $ttl = $res->{tokens}->[1];
    ok($ttl > 30 && $ttl <= 90, "TTL was modified");
    ok($cas != $res->{tokens}->[2], "CAS was updated");
    is($res->{tokens}->[0], 1, "size updated");
    is($res->{val}, "g", "value was updated");
}

# Quiet flag suppresses most output. Badly invalid commands will still
# generate something. Not weird to parse like 'noreply' token was...
# mget's with hits should return real data.
{
    diag "testing quiet flag";
    print $sock "mset quiet Sq 2\r\nmo\r\n";
    print $sock "mdelete quiet q\r\n";
    print $sock "mget quiet svq\r\n";
    diag "now purposefully cause an error\r\n";
    print $sock "mset quiet S\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR/, "resp not STORED, DELETED, or END");
}

{
    my $k = 'otest';
    diag "testing mget opaque";
    print $sock "mset $k ST 2 100\r\nra\r\n";
    like(scalar <$sock>, qr/^STORED/, "set $k");

    my $res = mget($sock, $k, 'stvo opaque');
    is($res->{tokens}->[2], 'opaque', "o flag returned opaque");
}

###

# takes hash:
# - sock
# - args (metaget flags)
# - array of tokens
# - array of expected response tokens

# returns hash:
# - win (if won a condition)
# - array of tokens
# - value, etc?
# useful to chain together for further requests.
# works only with single line values. no newlines in value.
# FIXME: some workaround for super long values :|
# TODO: move this to lib/MemcachedTest.pm
sub mget_is {
    # single line values only
    my ($o, $key, $val, $msg) = @_;

    my $dval = defined $val ? "'$val'" : "<undef>";
    $msg ||= "$key == $dval";

    my $s = $o->{sock};
    my $flags = $o->{flags};
    # sometimes response flags can differ from request flags.
    my $eflags = $o->{eflags} || $flags;
    my $tokens = exists $o->{tokens} ? join(' ', @{$o->{tokens}}) : '';
    my $etokens = exists $o->{etokens} ? join(' ', @{$o->{etokens}}) : '';

    print $s "mget $key $flags $tokens\r\n";
    if (! defined $val) {
        my $line = scalar <$s>;
        if ($line =~ /^VALUE/) {
            $line .= scalar(<$s>) . scalar(<$s>);
        }
        Test::More::is($line, "END\r\n", $msg);
    } else {
        my $len = length($val);
        my $body = scalar(<$s>);
        my $expected = "VALUE $key $eflags $etokens\r\n$val\r\nEND\r\n";
        if (!$body || $body =~ /^END/) {
            Test::More::is($body, $expected, $msg);
            return;
        }
        $body .= scalar(<$sock>) . scalar(<$sock>);
        Test::More::is($body, $expected, $msg);
        return mget_res($body);
    }
    return {};
}

# FIXME: skip value if no v in tokens!
sub mget {
    my $s = shift;
    my $key = shift;
    my $flags = shift;
    my $tokens = join(' ', @_);

    print $s "mget $key $flags ", $tokens, "\r\n";
    my $header = scalar(<$s>);
    my $val = "\r\n";
    if ($flags =~ m/v/) {
        $val = scalar(<$s>);
    }
    my $end = scalar(<$s>);

    return mget_res($header . $val);
}

# parse out a response
sub mget_res {
    my $resp = shift;
    my %r = ();

    if ($resp =~ m/^VALUE ([^\s]+) ([^\s]+) ([^\r]+)\r\n(.*)\r\n/gm) {
        $r{key} = $1;
        $r{flags} = $2;
        $r{val} = $4;
        $r{tokens} = [split(/ /, $3)];
    }

    return \%r;
}

done_testing();

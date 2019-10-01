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
# mg [key] [flags] [tokens]\r\n
# response:
# VA [flags] [tokens]\r\n
# data\r\n
# EN\r\n
#
# flags:
# - s: item size
# - v: return item value
# - c: return item cas
# - t: return item TTL remaining (-1 for unlimited)
# - f: client flags
# - l: last access time
# - h: whether item has been hit before
# - O: opaque to copy back.
# - k: return key
# - q: noreply semantics.
# - u: don't bump the item
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
# ms [key] [flags] [tokens]\r\n
# value\r\n
# response:
# ST [flags] [tokens]\r\n
# ST STORED, NS NOT_STORED, EX EXISTS, NF NOT_FOUND
#
# flags:
# - q: noreply
# - F (token): set client flags
# - C (token): compare CAS value
# - S (token): item size
# - T (token): TTL
# - O: opaque to copy back.
# - k: return key
# - I: invalid. set-to-invalid if CAS is older than it should be.
# Not implemented:
# - E: add if not exists (influences other options)
# - A: append (exclusive)
# - P: prepend (exclusive)
# - L: replace (exclusive)
# - incr/decr? pushing it, I guess.
#
# md [key] [flags] [tokens]\r\n
# response:
# DE [flags] [tokens]
# flags:
# - q: noreply
# - T (token): updates TTL
# - C (token): compare CAS value
# - I: invalidate. mark as stale, bumps CAS.
# - O: opaque to copy back.
# - k: return key
#
# mn\r\n
# response:
# EN

# metaget tests

# basic test
# - raw mget
# - raw mget miss
# - raw mget bad key

{
    print $sock "set foo 0 0 2\r\nhi\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored test value");

    print $sock "me none\r\n";
    is(scalar <$sock>, "EN\r\n", "raw mget miss");

    print $sock "me foo\r\n";
    like(scalar <$sock>, qr/^ME foo /, "raw mget result");
    # bleed the EN off the socket.
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
    print $sock "ms needwin CST 5000 2 120\r\nnu\r\n";
    like(scalar <$sock>, qr/^EX /, "failed to SET: CAS didn't match");

    # again, but succeed.
    # TODO: the actual CAS command should work here too?
    my $cas = $res->{tokens}->[1];
    print $sock "ms needwin CST $cas 2 120\r\nmu\r\n";
    like(scalar <$sock>, qr/^ST /, "SET: CAS matched");

    # now we repeat the original mget, but the data should be different.
    $res = mget($sock, 'needwin', 'sktcvN 30');
    ok(keys %$res, "not a miss");
    like($res->{flags}, qr/sktcvN/, "got main flags back");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    is($res->{tokens}->[1], 'needwin', "key matches");
    $ttl = $res->{tokens}->[2];
    ok($ttl > 100 && $ttl <= 120, "TTL is within requested window: $ttl");
    is($res->{val}, "mu", "value matches");

    # now we do the whole routine again, but for "triggered on TTL being low"
    # TTL was set to 120 just now, so anything lower than this should trigger.
    $res = mget($sock, 'needwin', 'stcvNR 30 130');
    like($res->{flags}, qr/stcvNR/, "got main flags back");
    like($res->{flags}, qr/W/, "got a win result");
    unlike($res->{flags}, qr/Z/, "no token already sent warning");
    is($res->{val}, "mu", "value matches");

    # try to fail this time.
    {
        my $res = mget($sock, 'needwin', 'stcvNR 30 130');
        ok(keys %$res, "got a non-empty response");
        unlike($res->{flags}, qr/W/, "not a win result");
        like($res->{flags}, qr/Z/, "object already sent win result");
        is($res->{val}, "mu", "value matches");
    }

    # again, but succeed.
    $cas = $res->{tokens}->[2];
    print $sock "ms needwin CST $cas 4 300\r\nzuuu\r\n";
    like(scalar <$sock>, qr/^ST /, "SET: CAS matched");

    # now we repeat the original mget, but the data should be different.
    $res = mget($sock, 'needwin', 'stcvN 30');
    ok(keys %$res, "not a miss");
    like($res->{flags}, qr/stcvN/, "got main flags back");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    $ttl = $res->{tokens}->[1];
    ok($ttl > 250 && $ttl <= 300, "TTL is within requested window");
    ok($res->{tokens}->[0] == 4, "Size returned correctly");
    is($res->{val}, "zuuu", "value matches: " . $res->{val});

}

# test get-and-touch mode
{
    # Set key with lower initial TTL.
    print $sock "ms gatkey ST 4 100\r\nooom\r\n";
    like(scalar <$sock>, qr/^ST /, "set gatkey");

    # Coolish side feature and/or bringer of bugs: 't' before 'T' gives TTL
    # before adjustment. 'T' before 't' gives TTL after adjustment.
    # Here we want 'T' before 't' to ensure we did adjust the value.
    my $res = mget($sock, 'gatkey', 'svTt 300');
    ok(keys %$res, "not a miss");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    my $ttl = $res->{tokens}->[1];
    ok($ttl > 280 && $ttl <= 300, "TTL is within requested window: $ttl");
}

# test no-value mode
{
    # Set key with lower initial TTL.
    print $sock "ms hidevalue ST 4 100\r\nhide\r\n";
    like(scalar <$sock>, qr/^ST /, "set hidevalue");

    my $res = mget($sock, 'hidevalue', 'st');
    ok(keys %$res, "not a miss");
    is($res->{val}, '', "no value returned");

    $res = mget($sock, 'hidevalue', 'stv');
    ok(keys %$res, "not a miss");
    is($res->{val}, 'hide', "real value returned");
}

# test hit-before? flag
{
    print $sock "ms hitflag ST 3 100\r\nhit\r\n";
    like(scalar <$sock>, qr/^ST /, "set hitflag");

    my $res = mget($sock, 'hitflag', 'sth');
    ok(keys %$res, "not a miss");
    is($res->{tokens}->[2], 0, "not been hit before");

    $res = mget($sock, 'hitflag', 'sth');
    ok(keys %$res, "not a miss");
    is($res->{tokens}->[2], 1, "been hit before");
}

# test no-update flag
{
    print $sock "ms noupdate ST 3 100\r\nhit\r\n";
    like(scalar <$sock>, qr/^ST /, "set noupdate");

    my $res = mget($sock, 'noupdate', 'stuh');
    ok(keys %$res, "not a miss");
    is($res->{tokens}->[2], 0, "not been hit before");

    # _next_ request should show a hit.
    # gets modified here but returns previous state.
    $res = mget($sock, 'noupdate', 'sth');
    is($res->{tokens}->[2], 0, "still not a hit");

    $res = mget($sock, 'noupdate', 'stuh');
    is($res->{tokens}->[2], 1, "finally a hit");
}

# test last-access time
{
    print $sock "ms la_test ST 2 100\r\nla\r\n";
    like(scalar <$sock>, qr/^ST /, "set la_test");
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
    print $sock "md toinv IT 30\r\n";
    like(scalar <$sock>, qr/^DE /, "mdelete'd key");

    # TODO: decide on if we need an explicit flag for "if I fetched a stale
    # value, does winning matter?
    # I think it's probably fine. clients can always ignore the win, or we can
    # add an option later to "don't try to revalidate if stale", perhaps.
    $res = mget($sock, 'toinv', 'stcv');
    ok(keys %$res, "not a miss");
    like($res->{flags}, qr/stcv/, "got main flags back");
    like($res->{flags}, qr/W/, "won the recache");
    like($res->{flags}, qr/X/, "item is marked stale");
    $ttl = $res->{tokens}->[1];
    ok($ttl > 0 && $ttl <= 30, "TTL is within requested window");
    ok($res->{tokens}->[0] == 3, "Size returned correctly");
    is($res->{val}, "moo", "value matches");

    diag "trying to fail then stale set via mset";
    print $sock "ms toinv STC 1 90 0\r\nf\r\n";
    like(scalar <$sock>, qr/^EX /, "failed to SET: low CAS didn't match");

    print $sock "ms toinv SITC 1 90 0\r\nf\r\n";
    like(scalar <$sock>, qr/^ST /, "SET an invalid/stale item");

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
    print $sock "ms toinv STC 1 90 $cas\r\ng\r\n";
    like(scalar <$sock>, qr/^ST /, "SET over the stale item");

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
    print $sock "ms quiet Sq 2\r\nmo\r\n";
    print $sock "md quiet q\r\n";
    print $sock "mg quiet svq\r\n";
    diag "now purposefully cause an error\r\n";
    print $sock "ms quiet S\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR/, "resp not ST, DE, or EN");

    # Now try a pipelined get. Throw an mnop at the end
    print $sock "ms quiet Sq 2\r\nbo\r\n";
    print $sock "mg quiet svq\r\nmg quiet svq\r\nmg quietmiss svq\r\nmn\r\n";
    # Should get back VA/data/VA/data/EN
    like(scalar <$sock>, qr/^VA svq 2/, "get response");
    like(scalar <$sock>, qr/^bo/, "get value");
    like(scalar <$sock>, qr/^VA svq 2/, "get response");
    like(scalar <$sock>, qr/^bo/, "get value");
    like(scalar <$sock>, qr/^EN/, "end token");
}

{
    my $k = 'otest';
    diag "testing mget opaque";
    print $sock "ms $k ST 2 100\r\nra\r\n";
    like(scalar <$sock>, qr/^ST /, "set $k");

    my $res = mget($sock, $k, 'stvO opaque');
    is($res->{tokens}->[2], 'opaque', "O flag returned opaque");
}

{
    diag "flag and token count errors";
    print $sock "mg foo sv extratoken\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR incorrect number of tokens/, "too many tokens");
    print $sock "mg foo svN\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR incorrect number of tokens/, "too few tokens");
    print $sock "mg foo mooooo\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR invalid or duplicate flag/, "gone silly with flags");
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

my $ext_path;
# Do a basic extstore test if enabled.
if (supports_extstore()) {
    diag "mget + extstore tests";
    $ext_path = "/tmp/extstore.$$";
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
              flags => 'sv',
              etokens => [20000] },
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

    print $sock "mg mfoo1 sv\r\n";
    is(scalar <$sock>, "EN\r\n");
    print $sock "mg mfoo1 svq\r\nmn\r\n";
    is(scalar <$sock>, "EN\r\n");
    $stats = mem_stats($sock);
    cmp_ok($stats->{miss_from_extstore}, '>', 0, 'at least one miss');
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

    print $s "mg $key $flags $tokens\r\n";
    if (! defined $val) {
        my $line = scalar <$s>;
        if ($line =~ /^VA/) {
            $line .= scalar(<$s>) . scalar(<$s>);
        }
        Test::More::is($line, "EN\r\n", $msg);
    } else {
        my $len = length($val);
        my $body = scalar(<$s>);
        my $expected = "VA $eflags $etokens\r\n$val\r\nEN\r\n";
        if (!$body || $body =~ /^EN/) {
            Test::More::is($body, $expected, $msg);
            return;
        }
        $body .= scalar(<$s>) . scalar(<$s>);
        Test::More::is($body, $expected, $msg);
        return mget_res($body);
    }
    return {};
}

sub mget {
    my $s = shift;
    my $key = shift;
    my $flags = shift;
    my $tokens = join(' ', @_);

    print $s "mg $key $flags ", $tokens, "\r\n";
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

    if ($resp =~ m/^VA ([^\s]+) ([^\r]+)\r\n(.*)\r\n/gm) {
        $r{flags} = $1;
        $r{val} = $3;
        $r{tokens} = [split(/ /, $2)];
    }

    return \%r;
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

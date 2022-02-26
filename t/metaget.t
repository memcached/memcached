#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

# command syntax:
# mg [key] [flags]\r\n
# response:
# VA [size] [flags]\r\n
# data\r\n
# or:
# HD [flags]\r\n
# or:
# EN\r\n
# flags are single 'f' or 'f1234' or 'fTEXT'
#
# flags:
# - s: return item size
# - v: return item value
# - c: return item cas
# - t: return item TTL remaining (-1 for unlimited)
# - f: return client flags
# - l: return last access time
# - h: return whether item has been hit before
# - O(token): opaque to copy back.
# - k: return key
# - q: noreply semantics.
# - u: don't bump the item in LRU
# updaters:
# - N(token): vivify on miss, takes TTL as a argument
# - R(token): if token is less than item TTL win for recache
# - T(token): update remaining TTL
# FIXME: do I need a "if stale and no token sent, flip" explicit flag?
# extra response flags:
# - W: client has "won" the token
# - X: object is stale
# - Z: object has sent a winning token
#
# ms [key] [valuelen] [flags]\r\n
# value\r\n
# response:
# HD [flags]\r\n
# HD STORED, NS NOT_STORED, EX EXISTS, NF NOT_FOUND
#
# flags:
# - q: noreply
# - F(token): set client flags
# - C(token): compare CAS value
# - T(token): TTL
# - O(token): opaque to copy back.
# - k: return key
# - I: invalid. set-to-invalid if CAS is older than it should be.
# - M(token): mode switch.
#   - default to "set"
#   - E: add mode
#   - A: append mode
#   - P: prepend mode
#   - R: replace mode
#   - S: set mode - not necessary, but could be useful for clients.
#
# md [key] [flags]\r\n
# response:
# HD [flags]
# flags:
# - q: noreply
# - T(token): updates TTL
# - C(token): compare CAS value
# - I: invalidate. mark as stale, bumps CAS.
# - O(token): opaque to copy back.
# - k: return key
#
# ma [key] [flags]\r\n
# response:
# HD [flags]\r\n
# HD, NS NOT_STORED, EX EXISTS, NF NOT_FOUND
# or:
# VA [size] [flags]\r\n
# data\r\n
#
# flags:
# q: noreply
# N(token): autovivify with supplied TTL
# J(token): initial value to use if autovivified
# D(token): delta to apply. default 1
# T(token): update TTL
# C(token): CAS must match
# M(token): mode switch.
#  - default to "incr"
#  - I: incr
#  - +: incr
#  - D: decr
#  - -: decr
# t: return TTL
# c: return current CAS
# v: return new value
#
# mn\r\n
# response:
# MN\r\n

# metaget tests

# basic test
# - raw mget
# - raw mget miss
# - raw mget bad key

# Test basic parser.
{
    print $sock " \n";
    is(scalar <$sock>, "ERROR\r\n", "error from blank command");
}

{
    print $sock "set foo 0 0 2\r\nhi\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored test value");

    print $sock "me none\r\n";
    is(scalar <$sock>, "EN\r\n", "raw mget miss");

    print $sock "me foo\r\n";
    like(scalar <$sock>, qr/^ME foo /, "raw mget result");
}

# mget with arguments
# - set some specific TTL and get it back (within reason)
# - get cas
# - autovivify and bit-win

{
    print $sock "set foo2 0 90 2\r\nho\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored test value");

    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's2' },
            'foo2', 'ho', "retrieved test value");

    # FIXME: figure out what I meant to do here.
    #my $res = mget($sock, 'foo2', 's t v');
}

{
    diag "basic mset CAS";
    my $key = "msetcas";
    print $sock "ms $key 2\r\nbo\r\n";
    like(scalar <$sock>, qr/^HD/, "set test key");

    my $res = mget($sock, $key, 'c');
    ok(get_flag($res, 'c'), "got a cas value back");

    my $cas = get_flag($res, 'c');
    my $badcas = $cas + 10;
    print $sock "ms $key 2 c C$badcas\r\nio\r\n";
    like(scalar <$sock>, qr/^EX c0/, "zeroed out cas on return");

    print $sock "ms $key 2 c C$cas\r\nio\r\n";
    like(scalar <$sock>, qr/^HD c\d+/, "success on correct cas");
}

{
    diag "mdelete with cas";
    my $key = "mdeltest";
    print $sock "ms $key 2\r\nzo\r\n";
    like(scalar <$sock>, qr/^HD/, "set test key");

    my $res = mget($sock, $key, 'c');
    ok(get_flag($res, 'c'), "got a cas value back");

    my $cas = get_flag($res, 'c');
    my $badcas = $cas + 10;
    print $sock "md $key C$badcas\r\n";
    like(scalar <$sock>, qr/^EX/, "mdelete fails for wrong CAS");
    print $sock "md $key C$cas\r\n";
    like(scalar <$sock>, qr/^HD/, "mdeleted key");
}

{
    diag "encoded binary keys";
    # 44OG44K544OI is "tesuto" in katakana
    my $tesuto = "44OG44K544OI";
    print $sock "ms $tesuto 2 b\r\npo\r\n";
    like(scalar <$sock>, qr/^HD/, "set with encoded key");

    my $res = mget($sock, $tesuto, 'v');
    ok(! exists $res->{val}, "encoded key doesn't exist");
    $res = mget($sock, $tesuto, 'b v k');
    ok(exists $res->{val}, "decoded key exists");
    ok(get_flag($res, 'k') eq $tesuto, "key returned encoded");

    # TODO: test k is returned properly from ms.
    # validate the store data is smaller somehow?
}

{
    diag "marithmetic tests";
    print $sock "ma mo\r\n";
    like(scalar <$sock>, qr/^NF/, "incr miss");

    print $sock "ma mo D1\r\n";
    like(scalar <$sock>, qr/^NF/, "incr miss with argument");

    print $sock "set mo 0 0 1\r\n1\r\n";
    like(scalar <$sock>, qr/^STORED/, "stored with set");

    print $sock "ma mo\r\n";
    like(scalar <$sock>, qr/^HD/, "incr'd a set value");

    print $sock "set mo 0 0 1\r\nq\r\n";
    like(scalar <$sock>, qr/^STORED/, "stored with set");

    print $sock "ma mo\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR /, "cannot incr non-numeric value");

    print $sock "ma mu N90\r\n";
    like(scalar <$sock>, qr/^HD/, "incr with seed");
    my $res = mget($sock, 'mu', 's t v Ofoo k');
    ok(keys %$res, "not a miss");
    ok(find_flags($res, 'st'), "got main flags back");
    is($res->{val}, '0', "seeded default value");
    my $ttl = get_flag($res, 't');
    ok($ttl > 10 && $ttl < 91, "TTL is within requested window: $ttl");

    $res = marith($sock, 'mu', 'T300 v t');
    ok(keys %$res, "not a miss");
    is($res->{val}, '1', "incremented once");
    $ttl = get_flag($res, 't');
    ok($ttl > 150 && $ttl < 301, "TTL is within requested window: $ttl");

    $res = marith($sock, 'mi', 'N0 J13 v t');
    ok(keys %$res, "not a miss");
    is($res->{val}, '13', 'seeded on a missed value');
    $res = marith($sock, 'mi', 'N0 J13 v t');
    is($res->{val}, '14', 'incremented from seed');

    $res = marith($sock, 'mi', 'N0 J13 v t D30');
    is($res->{val}, '44', 'specific increment');

    $res = marith($sock, 'mi', 'N0 J13 v t MD D22');
    is($res->{val}, '22', 'specific decrement');

    $res = marith($sock, 'mi', 'N0 J13 v t MD D9000');
    is($res->{val}, '0', 'land at 0 for over-decrement');

    print $sock "ma mi q D1\r\nmn\r\n";
    like(scalar <$sock>, qr/^MN/, "quiet increment");

    # CAS routines.
    $res = marith($sock, 'mc', 'N0 c v');
    my $cas = get_flag($res, 'c');
    # invalid CAS.
    print $sock "ma mc N0 C99999 v\r\n";
    like(scalar <$sock>, qr/^EX/, 'CAS mismatch');
    # valid CAS
    $res = marith($sock, 'mc', "N0 C$cas c v");
    my $ncas = get_flag($res, 'c');
    is($res->{val}, '1', 'ticked after CAS increment');
    isnt($cas, $ncas, 'CAS increments during modification');
}

# mset tests with mode switch flag (M)

{
    diag "mset mode switch";
    print $sock "ms modedefault 2 T120\r\naa\r\n";
    like(scalar <$sock>, qr/^HD/, "default set mode");
    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's2' },
            'modedefault', 'aa', "retrieved test value");

    # Fail an add
    print $sock "ms modedefault 2 T120 ME\r\naa\r\n";
    like(scalar <$sock>, qr/^NS/, "add mode gets NOT_STORED");
    # Win an add
    print $sock "ms modetest 2 T120 ME\r\nbb\r\n";
    like(scalar <$sock>, qr/^HD/, "add mode");
    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's2' },
            'modetest', 'bb', "retrieved test value");

    # append
    print $sock "ms modetest 2 T120 MA\r\ncc\r\n";
    like(scalar <$sock>, qr/^HD/, "append mode");
    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's4' },
            'modetest', 'bbcc', "retrieved test value");
    # prepend
    print $sock "ms modetest 2 T120 MP\r\naa\r\n";
    like(scalar <$sock>, qr/^HD/, "append mode");
    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's6' },
            'modetest', 'aabbcc', "retrieved test value");

    # replace
    print $sock "ms modereplace 2 T120 MR\r\nzz\r\n";
    like(scalar <$sock>, qr/^NS/, "fail replace mode");
    print $sock "ms modetest 2 T120 MR\r\nxx\r\n";
    like(scalar <$sock>, qr/^HD/, "replace mode");
    mget_is({ sock => $sock,
              flags => 's v',
              eflags => 's2' },
            'modetest', 'xx', "retrieved test value");

    # explicit set
    print $sock "ms modetest 2 T120 MS\r\nyy\r\n";
    like(scalar <$sock>, qr/^HD/, "force set mode");

    # invalid mode
    print $sock "ms modetest 2 T120 MZ\r\ntt\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR /, "invalid mode");
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
    my $res = mget($sock, 'needwin', 's c v N30 t');
    like($res->{flags}, qr/[scvNt]+/, "got main flags back");
    like($res->{flags}, qr/W/, "got a win result");
    unlike($res->{flags}, qr/Z/, "no token already sent warning");

    # asked for size and TTL. size should be 0, TTL should be > 0 and < 30
    is($res->{size}, 0, "got zero size: autovivified response");
    my $ttl = get_flag($res, 't');
    ok($ttl > 0 && $ttl <= 30, "auto TTL is within requested window: $ttl");

    # try to fail this time.
    {
        my $res = mget($sock, 'needwin', 's t c v N30');
        ok(keys %$res, "got a non-empty response");
        unlike($res->{flags}, qr/W/, "not a win result");
        like($res->{flags}, qr/Z/, "object already sent win result");
    }

    # set back with the wrong CAS
    print $sock "ms needwin 2 C5000 T120\r\nnu\r\n";
    like(scalar <$sock>, qr/^EX/, "failed to SET: CAS didn't match");

    # again, but succeed.
    # TODO: the actual CAS command should work here too?
    my $cas = get_flag($res, 'c');
    print $sock "ms needwin 2 C$cas T120\r\nmu\r\n";
    like(scalar <$sock>, qr/^HD/, "SET: CAS matched");

    # now we repeat the original mget, but the data should be different.
    $res = mget($sock, 'needwin', 's k t c v N30');
    ok(keys %$res, "not a miss");
    ok(find_flags($res, 'sktc'), "got main flags back");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    is(get_flag($res, 'k'), 'needwin', "key matches");
    $ttl = get_flag($res, 't');
    ok($ttl > 100 && $ttl <= 120, "TTL is within requested window: $ttl");
    is($res->{val}, "mu", "value matches");

    # now we do the whole routine again, but for "triggered on TTL being low"
    # TTL was set to 120 just now, so anything lower than this should trigger.
    $res = mget($sock, 'needwin', 's t c v N30 R130');
    ok(find_flags($res, 'stc'), "got main flags back");
    like($res->{flags}, qr/W/, "got a win result");
    unlike($res->{flags}, qr/Z/, "no token already sent warning");
    is($res->{val}, "mu", "value matches");

    # try to fail this time.
    {
        my $res = mget($sock, 'needwin', 's t c v N30 R130');
        ok(keys %$res, "got a non-empty response");
        unlike($res->{flags}, qr/W/, "not a win result");
        like($res->{flags}, qr/Z/, "object already sent win result");
        is($res->{val}, "mu", "value matches");
    }

    # again, but succeed.
    $cas = get_flag($res, 'c');
    print $sock "ms needwin 4 C$cas T300\r\nzuuu\r\n";
    like(scalar <$sock>, qr/^HD/, "SET: CAS matched");

    # now we repeat the original mget, but the data should be different.
    $res = mget($sock, 'needwin', 's t c v N30');
    ok(keys %$res, "not a miss");
    ok(find_flags($res, 'stc'), "got main flags back");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    $ttl = get_flag($res, 't');
    ok($ttl > 250 && $ttl <= 300, "TTL is within requested window");
    ok($res->{size} == 4, "Size returned correctly");
    is($res->{val}, "zuuu", "value matches: " . $res->{val});

}

# test get-and-touch mode
{
    # Set key with lower initial TTL.
    print $sock "ms gatkey 4 T100\r\nooom\r\n";
    like(scalar <$sock>, qr/^HD/, "set gatkey");

    # Coolish side feature and/or bringer of bugs: 't' before 'T' gives TTL
    # before adjustment. 'T' before 't' gives TTL after adjustment.
    # Here we want 'T' before 't' to ensure we did adjust the value.
    my $res = mget($sock, 'gatkey', 's v T300 t');
    ok(keys %$res, "not a miss");
    unlike($res->{flags}, qr/[WZ]/, "not a win or token result");
    my $ttl = get_flag($res, 't');
    ok($ttl > 280 && $ttl <= 300, "TTL is within requested window: $ttl");
}

# test no-value mode
{
    # Set key with lower initial TTL.
    print $sock "ms hidevalue 4 T100\r\nhide\r\n";
    like(scalar <$sock>, qr/^HD/, "set hidevalue");

    my $res = mget($sock, 'hidevalue', 's t');
    ok(keys %$res, "not a miss");
    is($res->{val}, undef, "no value returned");

    $res = mget($sock, 'hidevalue', 's t v');
    ok(keys %$res, "not a miss");
    is($res->{val}, 'hide', "real value returned");
}

# test hit-before? flag
{
    print $sock "ms hitflag 3 T100\r\nhit\r\n";
    like(scalar <$sock>, qr/^HD/, "set hitflag");

    my $res = mget($sock, 'hitflag', 's t h');
    ok(keys %$res, "not a miss");
    is(get_flag($res, 'h'), 0, "not been hit before");

    $res = mget($sock, 'hitflag', 's t h');
    ok(keys %$res, "not a miss");
    is(get_flag($res, 'h'), 1, "been hit before");
}

# test no-update flag
{
    print $sock "ms noupdate 3 T100\r\nhit\r\n";
    like(scalar <$sock>, qr/^HD/, "set noupdate");

    my $res = mget($sock, 'noupdate', 's t u h');
    ok(keys %$res, "not a miss");
    is(get_flag($res, 'h'), 0, "not been hit before");

    # _next_ request should show a hit.
    # gets modified here but returns previous state.
    $res = mget($sock, 'noupdate', 's t h');
    is(get_flag($res, 'h'), 0, "still not a hit");

    $res = mget($sock, 'noupdate', 's t u h');
    is(get_flag($res, 'h'), 1, "finally a hit");
}

# test last-access time
{
    print $sock "ms la_test 2 T100\r\nla\r\n";
    like(scalar <$sock>, qr/^HD/, "set la_test");
    sleep 2;

    my $res = mget($sock, 'la_test', 's t l');
    ok(keys %$res, "not a miss");
    isnt(get_flag($res, 'l'), 0, "been over a second since most recently accessed");
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

    $res = mget($sock, 'toinv', 's v');
    unlike($res->{flags}, qr/[XWZ]/, "no extra flags");

    # Lets mark the sucker as invalid, and drop its TTL to 30s
    diag "running mdelete";
    print $sock "md toinv I T30\r\n";
    like(scalar <$sock>, qr/^HD /, "mdelete'd key");

    # TODO: decide on if we need an explicit flag for "if I fetched a stale
    # value, does winning matter?
    # I think it's probably fine. clients can always ignore the win, or we can
    # add an option later to "don't try to revalidate if stale", perhaps.
    $res = mget($sock, 'toinv', 's t c v');
    ok(keys %$res, "not a miss");
    ok(find_flags($res, 'stc'), "got main flags back");
    like($res->{flags}, qr/W/, "won the recache");
    like($res->{flags}, qr/X/, "item is marked stale");
    $ttl = get_flag($res, 't');
    ok($ttl > 0 && $ttl <= 30, "TTL is within requested window");
    ok($res->{size} == 3, "Size returned correctly");
    is($res->{val}, "moo", "value matches");

    diag "trying to fail then stale set via mset";
    print $sock "ms toinv 1 T90 C0\r\nf\r\n";
    like(scalar <$sock>, qr/^EX/, "failed to SET: low CAS didn't match");

    print $sock "ms toinv 1 I T90 C1\r\nf\r\n";
    like(scalar <$sock>, qr/^HD/, "SET an invalid/stale item");

    diag "confirm item still stale, and TTL wasn't raised.";
    $res = mget($sock, 'toinv', 's t c v');
    like($res->{flags}, qr/X/, "item is marked stale");
    like($res->{flags}, qr/Z/, "win token already sent");
    unlike($res->{flags}, qr/W/, "didn't win: token already sent");
    $ttl = get_flag($res, 't');
    ok($ttl > 0 && $ttl <= 30, "TTL wasn't modified");

    # TODO: CAS too high?

    diag "do valid mset";
    $cas = get_flag($res, 'c');
    print $sock "ms toinv 1 T90 C$cas\r\ng\r\n";
    like(scalar <$sock>, qr/^HD/, "SET over the stale item");

    $res = mget($sock, 'toinv', 's t c v');
    ok(keys %$res, "not a miss");
    unlike($res->{flags}, qr/[WXZ]/, "no stale, win, or tokens");

    $ttl = get_flag($res, 't');
    ok($ttl > 30 && $ttl <= 90, "TTL was modified");
    ok($cas != get_flag($res, 'c'), "CAS was updated");
    is($res->{size}, 1, "size updated");
    is($res->{val}, "g", "value was updated");
}

# Quiet flag suppresses most output. Badly invalid commands will still
# generate something. Not weird to parse like 'noreply' token was...
# mget's with hits should return real data.
{
    diag "testing quiet flag";
    print $sock "ms quiet 2 q\r\nmo\r\n";
    print $sock "md quiet q\r\n";
    print $sock "mg quiet s v q\r\n";
    diag "now purposefully cause an error\r\n";
    print $sock "ms quiet\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR/, "resp not HD, or EN");

    # Now try a pipelined get. Throw an mnop at the end
    print $sock "ms quiet 2 q\r\nbo\r\n";
    print $sock "mg quiet v q\r\nmg quiet v q\r\nmg quietmiss v q\r\nmn\r\n";
    # Should get back VA/data/VA/data/EN
    like(scalar <$sock>, qr/^VA 2/, "get response");
    like(scalar <$sock>, qr/^bo/, "get value");
    like(scalar <$sock>, qr/^VA 2/, "get response");
    like(scalar <$sock>, qr/^bo/, "get value");
    like(scalar <$sock>, qr/^MN/, "end token");

    # "quiet" won't do anything with autoviv, since the only case (miss)
    # should return data anyway.
    print $sock "mg quietautov s N30 t q\r\n";
    like(scalar <$sock>, qr/^HD s0/, "quiet doesn't override autovivication");
}

{
    my $k = 'otest';
    diag "testing mget opaque";
    print $sock "ms $k 2 T100\r\nra\r\n";
    like(scalar <$sock>, qr/^HD/, "set $k");

    my $res = mget($sock, $k, 't v Oopaque');
    is(get_flag($res, 'O'), 'opaque', "O flag returned opaque");
}

{
    diag "flag and token count errors";
    print $sock "mg foo m o o o o o o o o o\r\n";
    like(scalar <$sock>, qr/^CLIENT_ERROR invalid flag/, "gone silly with flags");
}

{
    diag "pipeline test";
    print $sock "ms foo 2 T100\r\nna\r\n";
    like(scalar <$sock>, qr/^HD/, "set foo");
    print $sock "mg foo s\r\nmg foo s\r\nquit\r\nmg foo s\r\n";
    like(scalar <$sock>, qr/^HD /, "got resp");
    like(scalar <$sock>, qr/^HD /, "got resp");
    is(scalar <$sock>, undef, "final get didn't run");
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

# only fetches values without newlines in it.
sub mget {
    my $s = shift;
    my $key = shift;
    my $flags = shift;

    print $s "mg $key $flags\r\n";
    my $header = scalar(<$s>);
    my $val = "\r\n";
    if ($header =~ m/^VA/) {
        $val = scalar(<$s>);
    }

    return mget_res($header . $val);
}

# TODO: share with mget()?
sub marith {
    my $s = shift;
    my $key = shift;
    my $flags = shift;

    print $s "ma $key $flags\r\n";
    my $header = scalar(<$s>);
    my $val = "\r\n";
    if ($header =~ m/^VA/) {
        $val = scalar(<$s>);
    }

    return mget_res($header . $val);
}

# parse out a response
sub mget_res {
    my $resp = shift;
    my %r = ();

    if ($resp =~ m/^VA (\d+) ([^\r]+)\r\n(.*)\r\n/gm) {
        $r{size} = $1;
        $r{flags} = $2;
        $r{val} = $3;
    } elsif ($resp =~ m/^HD ([^\r]+)\r\n/gm) {
        $r{flags} = $1;
        $r{hd} = 1;
    }

    return \%r;
}

sub get_flag {
    my $res = shift;
    my $flag = shift;
    #print STDERR "FLAGS: $res->{flags}\n";
    my @flags = split(/ /, $res->{flags});
    for my $f (@flags) {
        if ($f =~ m/^$flag/) {
            return substr $f, 1;
        }
    }
}

sub find_flags {
    my $res = shift;
    my $flags = shift;
    my @flags = split(//, $flags);
    for my $f (@flags) {
        return 0 unless get_flag($res, $f);
    }
    return 1;
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}

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
# - q: noreply semantics.
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
#
# mdelete [key] [flags] [tokens]\r\n
# response:
# FIXME
# flags:
# - q: noreply
# - T (token): updates TTL
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

# need mset past here

# high level tests:
# - mget + mset with serve-stale
# - invalidate via mdelete and mget/revalidate with mset
#   - remember failure scenarios!
#   - also test re-setting as stale (extra double-bit dance)

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

sub mget {
    my $s = shift;
    my $key = shift;
    my $flags = shift;
    my @tokens = @_;

    print $s "mget $key $flags ", join(' ', @tokens), "\r\n";
    my $header = scalar(<$s>);
    my $val = scalar(<$s>);
    my $end = scalar(<$s>);

    return mget_res($header . $val);
}

# parse out a response
sub mget_res {
    my $resp = shift;
    my %r = ();

    if ($resp =~ m/^VALUE (.*) (.*) (.*)\r\n(.*)\r\n/gm) {
        $r{key} = $1;
        $r{flags} = $2;
        $r{val} = $4;
        $r{tokens} = [split(/ /, $3)];
    }

    return \%r;
}

done_testing();

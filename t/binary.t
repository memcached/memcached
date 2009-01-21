#!/usr/bin/perl

use strict;
use warnings;
use Test::More 'no_plan';
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
ok($server, "started the server");

# Based almost 100% off testClient.py which is:
# Copyright (c) 2007  Dustin Sallings <dustin@spy.net>

# Command constants
use constant CMD_GET     => 0x00;
use constant CMD_SET     => 0x01;
use constant CMD_ADD     => 0x02;
use constant CMD_REPLACE => 0x03;
use constant CMD_DELETE  => 0x04;
use constant CMD_INCR    => 0x05;
use constant CMD_DECR    => 0x06;
use constant CMD_QUIT    => 0x07;
use constant CMD_FLUSH   => 0x08;
use constant CMD_GETQ    => 0x09;
use constant CMD_NOOP    => 0x0A;
use constant CMD_VERSION => 0x0B;
use constant CMD_GETK    => 0x0C;
use constant CMD_GETKQ   => 0x0D;
use constant CMD_APPEND  => 0x0E;
use constant CMD_PREPEND => 0x0F;

# REQ and RES formats are divided even though they currently share
# the same format, since they _could_ differ in the future.
use constant REQ_PKT_FMT      => "CCnCCnNNNN";
use constant RES_PKT_FMT      => "CCnCCnNNNN";
use constant INCRDECR_PKT_FMT => "NNNNN";
use constant MIN_RECV_BYTES   => length(pack(RES_PKT_FMT));
use constant REQ_MAGIC        => 0x80;
use constant RES_MAGIC        => 0x81;

my $mc = MC::Client->new;

my $check = sub {
    my ($key, $orig_flags, $orig_val) = @_;
    my ($flags, $val, $cas) = $mc->get($key);
    is($flags, $orig_flags, "Flags is set properly");
};

my $set = sub {
    my ($key, $exp, $orig_flags, $orig_value) = @_;
    $mc->set($key, $orig_value, $orig_flags, $exp);
    $check->($key, $orig_flags, $orig_value);
};

my $empty = sub {
    my $key = shift;
    my $rv =()= eval { $mc->get($key) };
    is($rv, 0, "Didn't get a result from get");
    ok($@->not_found, "We got a not found error when we expected one");
};

my $delete = sub {
    my ($key, $when) = @_;
    $mc->delete($key, $when);
    $empty->($key);
};

diag "Test Version";
my $v = $mc->version;
ok(defined $v && length($v), "Proper version: $v");

diag "Flushing...";
$mc->flush;

diag "Noop";
$mc->noop;

diag "Simple set/get";
$set->('x', 5, 19, "somevalue");

diag "Delete";
$delete->('x');

diag "Flush";
$set->('x', 5, 19, "somevaluex");
$set->('y', 5, 17, "somevaluey");
$mc->flush;
$empty->('x');
$empty->('y');

{
    diag "Add";
    $empty->('i');
    $mc->add('i', 'ex', 5, 10);
    $check->('i', 5, "ex");

    my $rv =()= eval { $mc->add('i', "ex2", 10, 5) };
    is($rv, 0, "Add didn't return anything");
    ok($@->exists, "Expected exists error received");
    $check->('i', 5, "ex");
}

{
    diag "Too big.";
    $empty->('toobig');
    $mc->set('toobig', 'not too big', 10, 10);
    eval {
        my $bigval = ("x" x (1024*1024)) . "x";
        $mc->set('toobig', $bigval, 10, 10);
    };
    ok($@->too_big, "Was too big");
    $empty->('toobig');
}

{
    diag "Replace";
    $empty->('j');

    my $rv =()= eval { $mc->replace('j', "ex", 19, 5) };
    is($rv, 0, "Replace didn't return anything");
    ok($@->not_found, "Expected not_found error received");
    $empty->('j');
    $mc->add('j', "ex2", 14, 5);
    $check->('j', 14, "ex2");
    $mc->replace('j', "ex3", 24, 5);
    $check->('j', 24, "ex3");
}

{
    diag "MultiGet";
    $mc->add('xx', "ex", 1, 5);
    $mc->add('wye', "why", 2, 5);
    my $rv = $mc->get_multi(qw(xx wye zed));

    # CAS is returned with all gets.
    $rv->{xx}->[2]  = 0;
    $rv->{wye}->[2] = 0;
    is_deeply($rv->{xx}, [1, 'ex', 0], "X is correct");
    is_deeply($rv->{wye}, [2, 'why', 0], "Y is correct");
    is(keys(%$rv), 2, "Got only two answers like we expect");
}

diag "Test increment";
$mc->flush;
is($mc->incr("x"), 0, "First incr call is zero");
is($mc->incr("x"), 1, "Second incr call is one");
is($mc->incr("x", 211), 212, "Adding 211 gives you 212");
is($mc->incr("x", 2**33), 8589934804, "Blast the 32bit border");

diag "Test decrement";
$mc->flush;
is($mc->incr("x", undef, 5), 5, "Initial value");
is($mc->decr("x"), 4, "Decrease by one");
is($mc->decr("x", 211), 0, "Floor is zero");

{
    diag "CAS";
    $mc->flush;

    {
        my $rv =()= eval { $mc->set("x", "bad value", 19, 5, 0x7FFFFFFFFF) };
        is($rv, 0, "Empty return on expected failure");
        ok($@->not_found, "Error was 'not found' as expected");
    }

    $mc->add("x", "original value", 5, 19);

    my ($flags, $val, $i) = $mc->get("x");
    is($val, "original value", "->gets returned proper value");

    {
        my $rv =()= eval { $mc->set("x", "broken value", 19, 5, $i+1) };
        is($rv, 0, "Empty return on expected failure (1)");
        ok($@->exists, "Expected error state of 'exists' (1)");
    }

    $mc->set("x", "new value", 19, 5, $i);

    my ($newflags, $newval, $newi) = $mc->get("x");
    is($newval, "new value", "CAS properly overwrote value");

    {
        my $rv =()= eval { $mc->set("x", "replay value", 19, 5,  $i) };
        is($rv, 0, "Empty return on expected failure (2)");
        ok($@->exists, "Expected error state of 'exists' (2)");
    }
}

package MC::Client;

use strict;
use warnings;
use fields qw(socket);
use IO::Socket::INET;

sub new {
    my $self = shift;
    my $sock = $server->sock;
    $self = fields::new($self);
    $self->{socket} = $sock;
    return $self;
}

sub send_command {
    my $self = shift;
    die "Not enough args to send_command" unless @_ >= 4;
    my ($cmd, $key, $val, $opaque, $extra_header, $cas) = @_;

    $extra_header = '' unless defined $extra_header;
    my $keylen    = length($key);
    my $vallen    = length($val);
    my $extralen  = length($extra_header);
    my $datatype  = 0;  # field for future use
    my $reserved  = 0;  # field for future use
    my $totallen  = $keylen + $vallen + $extralen;
    my $ident_hi  = 0;
    my $ident_lo  = 0;

    if ($cas) {
        $ident_hi = int($cas / 2 ** 32);
        $ident_lo = int($cas % 2 ** 32);
    }

    my $msg = pack(::REQ_PKT_FMT, ::REQ_MAGIC, $cmd, $keylen, $extralen,
                   $datatype, $reserved, $totallen, $opaque, $ident_hi,
                   $ident_lo);

	  return $self->{socket}->send($msg . $extra_header . $key . $val);
}

sub _handle_single_response {
    my $self = shift;
    my $myopaque = shift;

    $self->{socket}->recv(my $response, ::MIN_RECV_BYTES);
    Test::More::is(length($response), ::MIN_RECV_BYTES, "Expected read length");

    my ($magic, $cmd, $keylen, $extralen, $datatype, $status, $remaining,
        $opaque, $ident_hi, $ident_lo) = unpack(::RES_PKT_FMT, $response);
    Test::More::is($magic, ::RES_MAGIC, "Got proper response magic");

    return ($opaque, '') if($remaining == 0);

    # fetch the value
    $self->{socket}->recv(my $rv, $remaining);

    if (defined $myopaque) {
        Test::More::is($opaque, $myopaque, "Expected opaque");
    } else {
        Test::More::pass("Implicit pass since myopaque is undefined");
    }

    my $cas = ($ident_hi * 2 ** 32) + $ident_lo;

    if ($status) {
        die MC::Error->new($status, $rv);
    }

    return ($opaque, $rv, $cas);
}

sub _do_command {
    my $self = shift;
    die unless @_ >= 3;
    my ($cmd, $key, $val, $extra_header, $cas) = @_;

    $extra_header = '' unless defined $extra_header;
    my $opaque = int(rand(2**32));
    $self->send_command($cmd, $key, $val, $opaque, $extra_header, $cas);
    my (undef, $rv, $rcas) = $self->_handle_single_response($opaque);
    return ($rv, $rcas);
}

sub _incrdecr {
    my $self = shift;
    my ($cmd, $key, $amt, $init, $exp) = @_;

    my $amt_hi = int($amt / 2 ** 32);
    my $amt_lo = int($amt % 2 ** 32);

    my $init_hi = int($init / 2 ** 32);
    my $init_lo = int($init % 2 ** 32);

    my $extra_header = pack(::INCRDECR_PKT_FMT, $amt_hi, $amt_lo, $init_hi,
                            $init_lo, $exp);

    my ($data, undef) = $self->_do_command($cmd, $key, '', $extra_header);

    my $header = substr $data, 0, 8, '';
    my ($resp_hi, $resp_lo) = unpack "NN", $header;
    my $resp = ($resp_hi * 2 ** 32) + $resp_lo;

    return $resp;
}

sub get {
    my $self = shift;
    my $key  = shift;
    my ($rv, $cas) = $self->_do_command(::CMD_GET, $key, '', '');

    my $header = substr $rv, 0, 4, '';
    my $flags  = unpack("N", $header);

    return ($flags, $rv, $cas);
}

sub get_multi {
    my $self = shift;
    my @keys = @_;

    for (my $i = 0; $i < @keys; $i++) {
        $self->send_command(::CMD_GETQ, $keys[$i], '', $i, '', 0);
    }

    my $terminal = @keys + 10;
	  $self->send_command(::CMD_NOOP, '', '', $terminal);

    my %return;
    while (1) {
        my ($opaque, $data) = $self->_handle_single_response;
        last if $opaque == $terminal;

        my $header = substr $data, 0, 4, '';
        my $flags  = unpack("N", $header);

        $return{$keys[$opaque]} = [$flags, $data];
    }

    return %return if wantarray;
    return \%return;
}

sub version {
    my $self = shift;
    return $self->_do_command(::CMD_VERSION, '', '');
}

sub flush {
    my $self = shift;
    return $self->_do_command(::CMD_FLUSH, '', '');
}

sub add {
    my $self = shift;
    my ($key, $val, $flags, $expire) = @_;
    my $extra_header = pack "NN", $flags, $expire;
    my $cas = 0;
    return $self->_do_command(::CMD_ADD, $key, $val, $extra_header, $cas);
}

sub set {
    my $self = shift;
    my ($key, $val, $flags, $expire, $cas) = @_;
    my $extra_header = pack "NN", $flags, $expire;
    return $self->_do_command(::CMD_SET, $key, $val, $extra_header, $cas);
}

sub replace {
    my $self = shift;
    my ($key, $val, $flags, $expire) = @_;
    my $extra_header = pack "NN", $flags, $expire;
    my $cas = 0;
    return $self->_do_command(::CMD_REPLACE, $key, $val, $extra_header, $cas);
}

sub delete {
    my $self = shift;
    my ($key) = @_;
    return $self->_do_command(::CMD_DELETE, $key, '');
}

sub incr {
    my $self = shift;
    my ($key, $amt, $init, $exp) = @_;
    $amt = 1 unless defined $amt;
    $init = 0 unless defined $init;
    $exp = 0 unless defined $exp;

    return $self->_incrdecr(::CMD_INCR, $key, $amt, $init, $exp);
}

sub decr {
    my $self = shift;
    my ($key, $amt, $init, $exp) = @_;
    $amt = 1 unless defined $amt;
    $init = 0 unless defined $init;
    $exp = 0 unless defined $exp;

    return $self->_incrdecr(::CMD_DECR, $key, $amt, $init, $exp);
}

sub noop {
    my $self = shift;
    return $self->_do_command(::CMD_NOOP, '', '');
}


package MC::Error;

use strict;
use warnings;

use constant ERR_UNKNOWN_CMD => 0x81;
use constant ERR_NOT_FOUND   => 0x1;
use constant ERR_EXISTS      => 0x2;
use constant ERR_TOO_BIG     => 0x3;

use overload '""' => sub {
    my $self = shift;
    return "Memcache Error ($self->[0]): $self->[1]";
};

sub new {
    my $class = shift;
    my $error = [@_];
    my $self = bless $error, (ref $class || $class);

    return $self;
}

sub not_found {
    my $self = shift;
    return $self->[0] == ERR_NOT_FOUND;
}

sub exists {
    my $self = shift;
    return $self->[0] == ERR_EXISTS;
}

sub too_big {
    my $self = shift;
    return $self->[0] == ERR_TOO_BIG;
}

# vim: filetype=perl


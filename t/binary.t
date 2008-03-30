#!/usr/bin/perl

use strict;
use warnings;
use Test::More 'no_plan';
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();

ok($server, "started the server");

# Based almost 100% off testClient.py which is Copyright (c) 2007  Dustin Sallings <dustin@spy.net>

# Command constants
use constant CMD_GET     => 0;
use constant CMD_SET     => 1;
use constant CMD_ADD     => 2;
use constant CMD_REPLACE => 3;
use constant CMD_DELETE  => 4;
use constant CMD_INCR    => 5;
use constant CMD_DECR    => 6;
use constant CMD_QUIT    => 7;
use constant CMD_FLUSH   => 8;
use constant CMD_GETQ    => 9;
use constant CMD_NOOP    => 10;
use constant CMD_VERSION => 11;

# CAS, Flags, expiration
use constant SET_PKT_FMT => "NNNN";

# Flags, expiration, id
use constant CAS_PKT_FMT => "NNNN";

# How long until the deletion takes effect.
use constant DEL_PKT_FMT => "N";

# amount, initial value, expiration
use constant INCRDECR_PKT_FMT => "NNNNN";

use constant REQ_MAGIC_BYTE => 0x80;
use constant RES_MAGIC_BYTE => 0x81;

use constant PKT_FMT => "CCnCxxxNN";

#min recv packet size
use constant MIN_RECV_PACKET => length(pack(PKT_FMT));

my $mc = MC::Client->new;
my $check = sub {
	my ($key, $orig_flags, $orig_value) = @_;
	my ($flags, $value) = $mc->get($key);
	is($flags, $orig_flags, "Flags is set properly");
	is($value, $orig_value, "Value is set properly");
};

my $set = sub {
	my ($key, $exp, $orig_flags, $orig_value) = @_;
	$mc->set($key, $exp, $orig_flags, $orig_value);
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

diag "Flushing...";
$mc->flush;

{
	diag "Test Version";
	my $v = $mc->version;
	ok(defined $v && length($v), "Proper version: $v");
}

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
	diag "Reservation delete";
	$set->('y', 5, 19, "someothervalue");
	$delete->('y', 1);
	my $rv =()= eval { $mc->add('y', 5, 19, "yetanothervalue") };
	is($rv, 0, "Add didn't return anything");
	ok($@->exists, "We got an exists error like we expected");
	sleep 2;
	$mc->add('y', 5, 19, "wibblevalue");
}

{
	diag "Add";
	$empty->('i');
        $mc->add('i', 5, 19, "ex");
        $check->('i', 19, "ex");

	my $rv =()= eval { $mc->add('i', 5, 19, "ex2") };
	is($rv, 0, "Add didn't return anything");
	ok($@->exists, "Expected exists error received");

	$check->('i', 19, "ex");
}

{
	diag "Replace";
	$empty->('j');

	my $rv =()= eval { $mc->replace('j', 5, 19, "ex") };
	is($rv, 0, "Replace didn't return anything");
	ok($@->not_found, "Expected not_found error received");

	$empty->('j');

	$mc->add('j', 5, 14, "ex2");
	$check->('j', 14, "ex2");

	$mc->replace('j', 5, 24, "ex3");
	$check->('j', 24, "ex3");
}

{
	diag "MultiGet";
	$mc->add('xx', 5, 1, "ex");
	$mc->add('wye', 5, 2, "why");
	my $rv = $mc->getMulti(qw(xx wye zed));

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
		my $rv =()= eval { $mc->set("x", 5, 19, "bad value", 0x7FFFFFFFFF) };
		is($rv, 0, "Empty return on expected failure");
		ok($@->not_found, "Error was 'not found' as expected");
	}

	$mc->add("x", 5, 19, "original value");

	my ($flags, $val, $i) = $mc->get("x");
	is($val, "original value", "->gets returned proper value");

    {
		my $rv =()= eval { $mc->set("x", 5, 19, "broken value", $i+1) };
		is($rv, 0, "Empty return on expected failure (1)");
		ok($@->exists, "Expected error state of 'exists' (1)");
	}

	$mc->set("x", 5, 19, "new value", $i);

	my ($newflags, $newval, $newi) = $mc->get("x");
	is($newval, "new value", "CAS properly overwrote value");

	{
		my $rv =()= eval { $mc->set("x", 5, 19, "replay value", $i) };
		is($rv, 0, "Empty return on expected failure (2)");
		ok($@->exists, "Expected error state of 'exists' (2)");
	}

	(undef, my $newval2) = $mc->get("x");
	is($newval2, "new value", "CAS replay didn't overwrite value");
}

$mc->flush;
$mc->close;


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

sub close {
	my $self = shift;
	return $self->{socket}->close(@_);
}

sub _sendCmd {
	my $self = shift;
	die "Not enough args to _sendCmd" unless @_ >= 4;
	my ($cmd, $key, $val, $opaque, $extraHeader) = @_;

	$extraHeader = '' unless defined $extraHeader;

	my $keylen = length($key);
	my $vallen = length($val);
	my $extralen = length($extraHeader);

	my $msg = pack(::PKT_FMT, ::REQ_MAGIC_BYTE, $cmd, $keylen, $extralen,
                    $keylen + $vallen + $extralen, $opaque);
	return $self->{socket}->send($msg . $extraHeader . $key . $val);
}

sub _handleSingleResponse {
	my $self = shift;
	my $myopaque = shift;

	$self->{socket}->recv(my $response, ::MIN_RECV_PACKET);

	Test::More::is(length($response), ::MIN_RECV_PACKET, "Expected read length");

	my ($magic, $cmd, $errcode, $extralen, $remaining,
        $opaque) = unpack(::PKT_FMT, $response);

	Test::More::is($magic, ::RES_MAGIC_BYTE, "Got proper magic");

	return ($opaque, "")
		if $remaining == 0;

	$self->{socket}->recv(my $rv, $remaining);

	if (defined $myopaque) {
		Test::More::is($opaque, $myopaque, "Expected opaque");
	} else {
		Test::More::pass("Implicit pass since myopaque is undefined");
	}

	if ($errcode) {
		die MC::Error->new($errcode, $rv);
	}

	return ($opaque, $rv);
}

sub _doCmd {
	my $self = shift;
	die unless @_ >= 3;
	my ($cmd, $key, $val, $extraHeader) = @_;

	$extraHeader = '' unless defined $extraHeader;

	my $opaque = int(rand(2**32));

	$self->_sendCmd($cmd, $key, $val, $opaque, $extraHeader);
	(undef, my $rv) = $self->_handleSingleResponse($opaque);
	return $rv;
}

sub __parseGet {
	my $self = shift;
	my $rv = shift; # currently contains 4 bytes of 'flag' followed by value
	my $header = substr $rv, 0, 12, '';
	my ($ident_hi, $ident_lo, $flags) = unpack "NNN", $header;
	my $ident = ($ident_hi * 2 ** 32) + $ident_lo;

	return $flags, $rv, $ident;
}

sub get {
	my $self = shift;
	my $key = shift;
	my $parts = $self->_doCmd(::CMD_GET, $key, '');
	return $self->__parseGet($parts);
}

sub _mutate {
	my $self = shift;
	my ($cmd, $key, $exp, $flags, $val, $ident) = @_;

    my $ident_hi = 0;
    my $ident_lo = 0;
    if ($ident) {
        $ident_hi = int($ident / 2 ** 32);
        $ident_lo = int($ident % 2 ** 32);
    }

	return $self->_doCmd($cmd, $key, $val, pack(::SET_PKT_FMT, $ident_hi, $ident_lo, $flags, $exp));
}

sub set {
	my $self = shift;
	my ($key, $exp, $flags, $val, $ident) = @_;

	return $self->_mutate(::CMD_SET, $key, $exp, $flags, $val, $ident);
}

sub __incrdecr {
	my $self = shift;
	my ($cmd, $key, $amt, $init, $exp) = @_;

	my $amt_hi = int($amt / 2 ** 32);
	my $amt_lo = int($amt % 2 ** 32);

	my $init_hi = int($init / 2 ** 32);
	my $init_lo = int($init % 2 ** 32);

	my $data = $self->_doCmd($cmd, $key, '', pack(::INCRDECR_PKT_FMT, $amt_hi, $amt_lo, $init_hi, $init_lo, $exp));
	my $header = substr $data, 0, 12, '';
	my ($resp_hi, $resp_lo) = unpack "NN", $header;
	my $resp = ($resp_hi * 2 ** 32) + $resp_lo;
    return $resp;
}

sub incr {
	my $self = shift;
	my ($key, $amt, $init, $exp) = @_;
	$amt = 1 unless defined $amt;
	$init = 0 unless defined $init;
	$exp = 0 unless defined $exp;

	return $self->__incrdecr(::CMD_INCR, $key, $amt, $init, $exp);
}

sub decr {
	my $self = shift;
	my ($key, $amt, $init, $exp) = @_;
	$amt = 1 unless defined $amt;
	$init = 0 unless defined $init;
	$exp = 0 unless defined $exp;

	return $self->__incrdecr(::CMD_DECR, $key, $amt, $init, $exp);
}

sub add {
	my $self = shift;
	my ($key, $exp, $flags, $val) = @_;
	return $self->_mutate(::CMD_ADD, $key, $exp, $flags, $val);
}
sub replace {
	my $self = shift;
	my ($key, $exp, $flags, $val) = @_;
	return $self->_mutate(::CMD_REPLACE, $key, $exp, $flags, $val);
}

sub getMulti {
	my $self = shift;
	my @keys = @_;

	for (my $i = 0; $i < @keys; $i++) {
		$self->_sendCmd(::CMD_GETQ, $keys[$i], '', $i);
	}

	my $terminal = @keys + 10;
	$self->_sendCmd(::CMD_NOOP, '', '', $terminal);

	my %return;

	while (1) {
		my ($opaque, $data) = $self->_handleSingleResponse;
		last if $opaque == $terminal;

		$return{$keys[$opaque]} = [$self->__parseGet($data)];
	}
	return %return if wantarray;
	return \%return;
}

sub noop {
	my $self = shift;
	return $self->_doCmd(::CMD_NOOP, '', '');
}

sub delete {
	my $self = shift;
	my ($key, $when) = @_;
	$when = 0 unless defined $when;

	return $self->_doCmd(::CMD_DELETE, $key, '', pack(::DEL_PKT_FMT, $when));
}

sub version {
	my $self = shift;
	return $self->_doCmd(::CMD_VERSION, '', '');
}

sub flush {
	my $self = shift;
	return $self->_doCmd(::CMD_FLUSH, '', '');
}

package MC::Error;

use strict;
use warnings;

use constant ERR_UNKNOWN_CMD => 0x81;
use constant ERR_NOT_FOUND   => 0x1;
use constant ERR_EXISTS      => 0x2;

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

# vim: filetype=perl

#!/usr/bin/perl

use strict;
use warnings;

use Test::More 'no_plan';

# Based almost 100% off testClient.py which is Copyright (c) 2007  Dustin Sallings <dustin@spy.net>

# Command constants
use constant CMD_GET     => 0;
use constant CMD_SET     => 1;
use constant CMD_ADD     => 2;
use constant CMD_REPLACE => 3;
use constant CMD_DELETE  => 4;
use constant CMD_INCR    => 5;
use constant CMD_QUIT    => 6;
use constant CMD_FLUSH   => 7;
use constant CMD_GETQ    => 8;
use constant CMD_NOOP    => 9;
use constant CMD_VERSION => 10;

use constant CMD_GETS    => 50;
use constant CMD_CAS     => 51;

# Flags, expiration
use constant SET_PKT_FMT => "NN";

# Flags, expiration, id
use constant CAS_PKT_FMT => "NNNN";

# How long until the deletion takes effect.
use constant DEL_PKT_FMT => "N";

# amount, initial value, expiration
use constant INCRDECR_PKT_FMT => "NNNNN";

use constant REQ_MAGIC_BYTE => 0x0f;
use constant RES_MAGIC_BYTE => 0xf0;

use constant PKT_FMT => "CCCxNN";

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

$mc->flush;

{
	diag "Test Version";
	my $v = $mc->version;
	ok(defined $v && length($v), "Proper version");
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

	is_deeply([1, 'ex'], $rv->{xx}, "X is correct");
	is_deeply([2, 'why'], $rv->{wye}, "Y is correct");
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

<<EOT;
    def testIncrDoesntExistNoCreate(self):
        """Testing incr when a value doesn't exist (and not creating)."""
        try:
            self.mc.incr("x", exp=-1)
            self.fail("Expected failure to increment non-existent key")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_NOT_FOUND, e.status)
        self.assertNotExists("x")

    def testIncrDoesntExistCreate(self):
        """Testing incr when a value doesn't exist (and we make a new one)"""
        self.assertNotExists("x")
        self.assertEquals(19, self.mc.incr("x", init=19))

    def testDecrDoesntExistNoCreate(self):
        """Testing decr when a value doesn't exist (and not creating)."""
        try:
            self.mc.decr("x", exp=-1)
            self.fail("Expected failiure to decrement non-existent key.")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_NOT_FOUND, e.status)
        self.assertNotExists("x")

    def testDecrDoesntExistCreate(self):
        """Testing decr when a value doesn't exist (and we make a new one)"""
        self.assertNotExists("x")
        self.assertEquals(19, self.mc.decr("x", init=19))
EOT

{
	diag "CAS";
	$mc->flush;

	{
		my $rv =()= eval { $mc->cas("x", 5, 19, 0x7FFFFFFFFF, "bad value") };
		is($rv, 0, "Empty return on expected failure");
		ok($@->not_found, "Error was 'not found' as expected");
	}

	$mc->add("x", 5, 19, "original value");

	my ($flags, $i, $val) = $mc->gets("x");
	is($val, "original value", "->gets returned proper value");

	{
		my $rv =()= eval { $mc->cas("x", 5, 19, $i+1, "broken value") };
		is($rv, 0, "Empty return on expected failure (1)");
		ok($@->exists, "Expected error state of 'exists' (1)");
	}

	$mc->cas("x", 5, 19, $i, "new value");

	my ($newflags, $newi, $newval) = $mc->gets("x");
	is($newval, "new value", "CAS properly overwrote value");

	{
		my $rv =()= eval { $mc->cas("x", 5, 19, $i, "replay value") };
		is($rv, 0, "Empty return on expected failure (2)");
		ok($@->exists, "Expected error state of 'exists' (2)");
	}

	(undef, undef, my $newval2) = $mc->gets("x");
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

	my $host = shift || '127.0.0.1';
	my $port = shift || 11212;

	my $sock = IO::Socket::INET->new(PeerHost => $host, PeerPort => $port);

	unless ($sock) {
		warn "Unable to contact memcached.";
		return;
	}

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

	my $msg = pack(::PKT_FMT, ::REQ_MAGIC_BYTE, $cmd, $keylen, $opaque, $keylen + $vallen + $extralen);
	return $self->{socket}->send($msg . $extraHeader . $key . $val);
}

sub _handleSingleResponse {
	my $self = shift;
	my $myopaque = shift;

	$self->{socket}->recv(my $response, ::MIN_RECV_PACKET);

	Test::More::is(length($response), ::MIN_RECV_PACKET, "Expected read length");

	my ($magic, $cmd, $errcode, $opaque, $remaining) = unpack(::PKT_FMT, $response);

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
	my $flag = substr $rv, 0, 4, ''; # Now $flag contains flags, $rv contains value
	return unpack("N", $flag), $rv;
}

sub get {
	my $self = shift;
	my $key = shift;
	my $parts = $self->_doCmd(::CMD_GET, $key, '');
	return $self->__parseGet($parts);
}

sub _mutate {
	my $self = shift;
	my ($cmd, $key, $exp, $flags, $val) = @_;

	return $self->_doCmd($cmd, $key, $val, pack(::SET_PKT_FMT, $flags, $exp));
}

sub set {
	my $self = shift;
	my ($key, $exp, $flags, $val) = @_;

	return $self->_mutate(::CMD_SET, $key, $exp, $flags, $val);
}

sub __incrdecr {
	my $self = shift;
	my ($cmd, $key, $amt, $init, $exp) = @_;

	my $amt_hi = int($amt / 2 ** 32);
	my $amt_lo = int($amt % 2 ** 32);

	my $init_hi = int($init / 2 ** 32);
	my $init_lo = int($init % 2 ** 32);

	return $self->_doCmd($cmd, $key, '', pack(::INCRDECR_PKT_FMT, $amt_hi, $amt_lo, $init_hi, $init_lo, $exp));
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

	return $self->__incrdecr(::CMD_INCR, $key, 0 - $amt, $init, $exp);
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

sub gets {
	my $self = shift;
	my $key = shift;

	my $data = $self->_doCmd(::CMD_GETS, $key, '');
	my $header = substr $data, 0, 12, '';
	my ($flags, $ident_hi, $ident_lo) = unpack "NNN", $header;
	my $ident = ($ident_hi * 2 ** 32) + $ident_lo;

	return $flags, $ident, $data;
}

sub cas {
	my $self = shift;
	my ($key, $exp, $flags, $oldVal, $val) = @_;

	my $oldVal_hi = int($oldVal / 2 ** 32);
	my $oldVal_lo = int($oldVal % 2 ** 32);

	return $self->_doCmd(::CMD_CAS, $key, $val, pack(::CAS_PKT_FMT, $flags, $exp, $oldVal_hi, $oldVal_lo));
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

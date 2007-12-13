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
# CMD_QUIT = 6
use constant CMD_FLUSH   => 7;
# CMD_GETQ = 8
use constant CMD_NOOP    => 9;
use constant CMD_VERSION => 10;
#
# CMD_GETS = 50
# CMD_CAS = 51
#
# Flags, expiration
use constant SET_PKT_FMT => "NN";
# flags, expiration, id
# CAS_PKT_FMT=">IiQ"
#
# How long until the deletion takes effect.
use constant DEL_PKT_FMT => "N";
#
# amount, initial value, expiration
use constant INCRDECR_PKT_FMT => "NNNNN";
#
use constant REQ_MAGIC_BYTE => 0x0f;
use constant RES_MAGIC_BYTE => 0xf0;
#
use constant PKT_FMT => "CCCxNN";
#min recv packet size
use constant MIN_RECV_PACKET => length(pack(PKT_FMT));
#
#

my $mc = MC::Client->new;
$mc->flush;

diag "Test Version";
{
	my $v = $mc->version;
	ok(defined $v && length($v), "Proper version");
}

my $set = sub {
	my ($key, $exp, $orig_flags, $orig_value) = @_;
	$mc->set($key, $exp, $orig_flags, $orig_value);
	my ($flags, $value) = $mc->get($key);
	is($flags, $orig_flags, "Flags is set properly");
	is($value, $orig_value, "Value is set properly");
};

diag "Noop";
$mc->noop;

diag "Simple set/get";
$set->('x', 5, 19, "somevalue");

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

diag "Delete";
$delete->('x');

diag "Flush";
{
	$set->('x', 5, 19, "somevaluex");
	$set->('y', 5, 17, "somevaluey");
	$mc->flush;
	$empty->('x');
	$empty->('y');
}

diag "Test increment";
{
	$mc->flush;
	is($mc->incr("x"), 0, "First incr call is zero");
	is($mc->incr("x"), 1, "Second incr call is one");
	is($mc->incr("x", 211), 212, "Adding 211 gives you 212");
	is($mc->incr("x", 2**33), 858993480, "Blast the 32bit border");
}

diag "Reservation delete";
{
	$set->('y', 5, 19, "someothervalue");
	$delete->('y', 1);
	my $rv =()= eval { $mc->add('y', 5, 19, "yetanothervalue") };
	is($rv, 0, "Add didn't return anything");
	ok($@->exists, "We got an exists error like we expected");
	sleep 2;
	$mc->add('y', 5, 19, "wibblevalue");
}

<<EOT;

    def testAdd(self):
        """Test add functionality."""
        self.assertNotExists("x")
        self.mc.add("x", 5, 19, "ex")
        self.assertEquals((19, "ex"), self.mc.get("x"))
        try:
            self.mc.add("x", 5, 19, "ex2")
            self.fail("Expected failure to add existing key")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_EXISTS, e.status)
        self.assertEquals((19, "ex"), self.mc.get("x"))

    def testReplace(self):
        """Test replace functionality."""
        self.assertNotExists("x")
        try:
            self.mc.replace("x", 5, 19, "ex")
            self.fail("Expected failure to replace missing key")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_NOT_FOUND, e.status)
        self.mc.add("x", 5, 19, "ex")
        self.assertEquals((19, "ex"), self.mc.get("x"))
        self.mc.replace("x", 5, 19, "ex2")
        self.assertEquals((19, "ex2"), self.mc.get("x"))

    def testMultiGet(self):
        """Testing multiget functionality"""
        self.mc.add("x", 5, 1, "ex")
        self.mc.add("y", 5, 2, "why")
        vals=self.mc.getMulti('xyz')
        self.assertEquals((1, 'ex'), vals['x'])
        self.assertEquals((2, 'why'), vals['y'])
        self.assertEquals(2, len(vals))

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

    def testCas(self):
        """Test CAS operation."""
        try:
            self.mc.cas("x", 5, 19, 0x7fffffffff, "bad value")
            self.fail("Expected error CASing with no existing value")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_NOT_FOUND, e.status)
        self.mc.add("x", 5, 19, "original value")
        flags, i, val=self.mc.gets("x")
        self.assertEquals("original value", val)
        try:
            self.mc.cas("x", 5, 19, i+1, "broken value")
            self.fail("Expected error CASing with invalid id")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_EXISTS, e.status)
        self.mc.cas("x", 5, 19, i, "new value")
        newflags, newi, newval=self.mc.gets("x")
        self.assertEquals("new value", newval)

        # Test a CAS replay
        try:
            self.mc.cas("x", 5, 19, i, "crap value")
            self.fail("Expected error CASing with invalid id")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_EXISTS, e.status)
        newflags, newi, newval=self.mc.gets("x")
        self.assertEquals("new value", newval)
EOT

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
	return $self->_doCmd($cmd, $key, '', pack(::INCRDECR_PKT_FMT, $amt >> 32, 0xFFFFFFFF & $amt, $init >> 32, 0xFFFFFFFF & $init, $exp));
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

<<EOT;
    def gets(self, key):
        """Get with an identifier (for cas)."""
        data=self._doCmd(memcacheConstants.CMD_GETS, key, '')
        parts=struct.unpack(">IQ", data[:12])
        return parts[0], parts[1], data[12:]

    def cas(self, key, exp, flags, oldVal, val):
        """CAS in a new value for the given key and comparison value."""
        self._doCmd(memcacheConstants.CMD_CAS, key, val,
            struct.pack(CAS_PKT_FMT, flags, exp, oldVal))

    def getMulti(self, keys):
        """Get values for any available keys in the given iterable.

        Returns a dict of matched keys to their values."""
        opaqued=dict(enumerate(keys))
        terminal=len(opaqued)+10
        # Send all of the keys in quiet
        for k,v in opaqued.iteritems():
            self._sendCmd(memcacheConstants.CMD_GETQ, v, '', k)

        self._sendCmd(memcacheConstants.CMD_NOOP, '', '', terminal)

        # Handle the response
        rv={}
        done=False
        while not done:
            opaque, data=self._handleSingleResponse(None)
            if opaque != terminal:
                rv[opaqued[opaque]]=self.__parseGet(data)
            else:
                done=True

        return rv

EOT

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

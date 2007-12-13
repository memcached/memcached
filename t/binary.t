#!/usr/bin/perl

use strict;
use warnings;

use Test::More 'no_plan';

# Based almost 100% off testClient.py which is Copyright (c) 2007  Dustin Sallings <dustin@spy.net>

# Command constants
use constant CMD_GET => 0;
use constant CMD_SET => 1;
# CMD_ADD = 2
# CMD_REPLACE = 3
use constant CMD_DELETE => 4;
# CMD_INCR = 5
# CMD_QUIT = 6
use constant CMD_FLUSH => 7;
# CMD_GETQ = 8
# CMD_NOOP = 9
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
# INCRDECR_PKT_FMT=">qQi"
#
use constant REQ_MAGIC_BYTE => 0x0f;
use constant RES_MAGIC_BYTE => 0xf0;
#
use constant PKT_FMT => "CCCxNN";
#min recv packet size
use constant MIN_RECV_PACKET => length(pack(PKT_FMT));
#
#
#ERR_UNKNOWN_CMD = 0x81
#ERR_NOT_FOUND = 0x1
#ERR_EXISTS = 0x2

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

diag "Simple set/get";
$set->('x', 5, 19, "somevalue");

my $delete = sub {
	my ($key) = @_;
	$mc->delete($key);
	my $rv =()= $mc->get($key);
	is($rv, 0, "Empty array from get means nothing stored here");
};

diag "Delete";
$delete->('x');

<<EOT;
    def testReservedDelete(self):
        """Test a delete with a reservation timestamp."""
        self.mc.set("x", 5, 19, "somevalue")
        self.assertEquals((19, "somevalue"), self.mc.get("x"))
        self.mc.delete("x", 1)
        self.assertNotExists("x")
        try:
            self.mc.add("x", 5, 19, "ex2")
            self.fail("Expected failure to add during timed delete")
        except MemcachedError, e:
            self.assertEquals(memcacheConstants.ERR_EXISTS, e.status)
        time.sleep(1.1)
        self.mc.add("x", 5, 19, "ex2")

    def testFlush(self):
        """Test flushing."""
        self.mc.set("x", 5, 19, "somevaluex")
        self.mc.set("y", 5, 17, "somevaluey")
        self.assertEquals((19, "somevaluex"), self.mc.get("x"))
        self.assertEquals((17, "somevaluey"), self.mc.get("y"))
        self.mc.flush()
        self.assertNotExists("x")
        self.assertNotExists("y")

    def testNoop(self):
        """Making sure noop is understood."""
        self.mc.noop()

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

    def testIncr(self):
        """Simple incr test."""
        val=self.mc.incr("x")
        self.assertEquals(0, val)
        val=self.mc.incr("x")
        self.assertEquals(1, val)
        val=self.mc.incr("x", 211)
        self.assertEquals(212, val)
        val=self.mc.incr("x", 2**33)
        self.assertEquals(8589934804L, val)

    def testDecr(self):
        """Simple decr test."""
        val=self.mc.incr("x", init=5)
        self.assertEquals(5, val)
        val=self.mc.decr("x")
        self.assertEquals(4, val)
        val=self.mc.decr("x", 211)
        self.assertEquals(0, val)

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
		die "Memcache error ($errcode): $rv\n";
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

<<EOT;
    def __incrdecr(self, cmd, key, amt, init, exp):
        return long(self._doCmd(cmd, key, '',
            struct.pack(memcacheConstants.INCRDECR_PKT_FMT, amt, init, exp)))

    def incr(self, key, amt=1, init=0, exp=0):
        """Increment or create the named counter."""
        return self.__incrdecr(memcacheConstants.CMD_INCR, key, amt, init, exp)

    def decr(self, key, amt=1, init=0, exp=0):
        """Decrement or create the named counter."""
        return self.__incrdecr(memcacheConstants.CMD_INCR, key, 0-amt, init,
            exp)

    def add(self, key, exp, flags, val):
        """Add a value in the memcached server iff it doesn't already exist."""
        self._mutate(memcacheConstants.CMD_ADD, key, exp, flags, val)

    def replace(self, key, exp, flags, val):
        """Replace a value in the memcached server iff it already exists."""
        self._mutate(memcacheConstants.CMD_REPLACE, key, exp, flags, val)

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

    def noop(self):
        """Send a noop command."""
        self._doCmd(memcacheConstants.CMD_NOOP, '', '')

    def delete(self, key, when=0):
        """Delete the value for a given key within the memcached server."""
        self._doCmd(memcacheConstants.CMD_DELETE, key, '',
            struct.pack(DEL_PKT_FMT, when))

EOT

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


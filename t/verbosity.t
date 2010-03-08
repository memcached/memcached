#!/usr/bin/perl
use strict;
use Test::More tests => 6;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

print $sock "verbosity foo bar my\r\n";
is(scalar <$sock>, "ERROR\r\n", "Illegal number of arguments");

print $sock "verbosity noreply\r\n";
is(scalar <$sock>, "ERROR\r\n", "Illegal noreply");

print $sock "verbosity 0\r\n";
is(scalar <$sock>, "OK\r\n", "Correct syntax");

my $settings = mem_stats($sock, 'settings');
is('0', $settings->{'verbosity'}, "Verify settings");

print $sock "verbosity foo\r\n";
is(scalar <$sock>, "ERROR\r\n", "Not a numeric argument");

print $sock "verbosity 1 noreply\r\n";
# should not generate an output...

$settings = mem_stats($sock, 'settings');
is('1', $settings->{'verbosity'}, "Verify settings");

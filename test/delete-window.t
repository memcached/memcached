#!/usr/bin/perl

use strict;
use Test::More tests => 14;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;
my $line = sub { return scalar <$sock> };

# immediate set/deletes
print $sock "set foo 0 0 6\r\nfooval\r\ndelete foo\r\nset foo 0 0 6\r\nfooval\r\ndelete foo\r\n";
is($line->(), "STORED\r\n",  "pipeline set");
is($line->(), "DELETED\r\n", "pipeline delete");
is($line->(), "STORED\r\n",  "pipeline set");
is($line->(), "DELETED\r\n", "pipeline delete");

# not found test
print $sock "delete foo\r\n";
is($line->(), "NOT_FOUND\r\n", "thing not found to delete");

# test the cool-down window (see protocol doc) whereby add/replace commands can't
# work n seconds after deleting.
print $sock "set foo 0 0 3\r\nbar\r\n";
is($line->(), "STORED\r\n", "stored foo");
print $sock "delete foo 1\r\n";
is($line->(), "DELETED\r\n", "deleted with 1 second window");
print $sock "get foo\r\n";
is($line->(), "END\r\n", "nothing found");
print $sock "add foo 0 0 7\r\nfoo-add\r\n";
is($line->(), "NOT_STORED\r\n", "didn't add foo");
print $sock "replace foo 0 0 11\r\nfoo-replace\r\n";
is($line->(), "NOT_STORED\r\n", "didn't replace foo");
print $sock "set foo 0 0 7\r\nfoo-set\r\n";
is($line->(), "STORED\r\n", "stored foo-set");

# add can work after expiration time
print $sock "set foo 0 0 3\r\nbar\r\n";
is($line->(), "STORED\r\n", "stored foo");
print $sock "delete foo 1\r\n";
is($line->(), "DELETED\r\n", "deleted with 1 second window");
sleep(1.2);
print $sock "add foo 0 0 7\r\nfoo-add\r\n";
is($line->(), "STORED\r\n", "stored foo-add");

# wait fo
diag("waiting 5 seconds for the deleter event...");
sleep(5.2);
print $sock "get foo\r\n";
is($line->(), "VALUE foo 0 7\r\n", "got foo value...");
is($line->(), "foo-add\r\n", ".. with value foo-add");
is($line->(), "END\r\n", "got END");


__END__
sleep 10;

# test a set, delete w/ timer, set, wait 5.2 seconds (for 5 second
# deleter event), then get to see which we get.
print $sock "set baz 0 0 4\r\nval1\r\n";
is($line->(), "STORED\r\n", "stored baz = val1");
print $sock "delete foo 1\r\n";
is($line->(), "DELETED\r\n", "deleted with 1 second window");

print $sock "set baz 0 0 4\r\nval2\r\n";
is($line->(), "STORED\r\n", "stored baz = val2");
diag("sleeping for 5 seconds to wait for deleter event...");
sleep(5.2);
print $sock "get baz\r\n";
is($line->(), "VALUE baz 0 4\r\n", "got baz value...");
is($line->(), "val2\r\n", ".. with value val2");
is($line->(), "END\r\n", "got END");



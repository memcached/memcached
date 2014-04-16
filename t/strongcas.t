#!/usr/bin/perl

use strict;
use Test::More tests => 61;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;


my $server = new_memcached(" -n 16 -z 0x3333:0xffff ");
my $sock = $server->sock;
my $sock2 = $server->new_sock;
my $lease_flag=0x3333;

my @result;
my @result2;
my $identifier1=0;
my $temp;

ok($sock != $sock2, "have two different connections open");

#print $sock "set foo 5555 100 6\r\nbarval\r\n";
#is(scalar <$sock>, "STORED\r\n", "stored barval");

#1) Retrieval command:
#----------------------
# getss foo (should return a new lease)
@result = mem_getss($sock, 3, "foo");
is(@result[0], "1", "getss  identifier:@result[0]");
like(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];

# getss foo again(should return a old lease)
@result = mem_getss($sock, 1000,"foo");
is(@result[0], "1", "getss  identifier:@result[0]");
unlike(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");


# gets/get foo (should not get the lease)
print $sock "gets foo\r\n";
is(scalar <$sock>, "END\r\n", "donot gets the lease");
print $sock "get foo\r\n";
is(scalar <$sock>, "END\r\n", "donot get the lease");



#2) Storage commands:
#--------------------------
# set foo, it is dirty by the lease. the expiration time is 3s.
print $sock "set foo 0 100 6\r\nbarval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored barval");

# getss foo and verify identifier increase, not lease
@result = mem_getss($sock, 100,"foo");
mem_getss_is($sock,$result[0],"foo","barval");
is(@result[0], $identifier1+1, "getss  identifier:@result[0]");
is(@result[2], 0, "getss   flag:0 == @result[2]");
$identifier1=@result[0];

sleep(4);
# gets/get foo (should not get the lease)
print $sock "gets foo\r\n";
is(scalar <$sock>, "END\r\n", "key is expired");

# getss foo (should return a new lease again)
@result = mem_getss($sock, 3,"foo");
is(@result[0], $identifier1+1, "getss  identifier:@result[0]");
like(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];

# cas fail
print $sock "cas foo 0 0 6 123\r\nbarva2\r\n";
is(scalar <$sock>, "EXISTS\r\n", "cas failed for foo");

# gets/get foo (still a leass item, should not get the lease)
print $sock "gets foo\r\n";
is(scalar <$sock>, "END\r\n", "key is expired");

#getss(get the old lease)
@result = mem_getss($sock, "10000","foo");

is(@result[0], $identifier1, "getss identifier: $identifier1");
unlike(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss wrong lease flag: @result[2]");
$identifier1=@result[0];

# cas success
print $sock "cas foo 0 0 6 $identifier1\r\nbarva2\r\n";
is(scalar <$sock>, "STORED\r\n", "cas success, set foo");

# cas failure (reusing the same key)
print $sock "cas foo 0 0 6 $identifier1\r\nbarva2\r\n";
is(scalar <$sock>, "EXISTS\r\n", "reusing a CAS ID");
#getss(get the new item, not a lease)
@result = mem_getss($sock, "10000","foo");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
isnt(@result[2], $lease_flag, "getss  lease flag: @result[2]");
mem_getss_is($sock,$result[0],"foo","barva2");
$identifier1=@result[0];

#3) Deletion command:
#---------------------------
# deletess a exist lease foo
print $sock "deletess 99 foo\r\n";
like(scalar <$sock>, qr/^DELETED\s\d*\s*/, "deletess foo");
#getss(get a new lease)
@result = mem_getss($sock, "10000","foo");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
like(@result[1], qr/^9\d\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];

# deletess a not exist lease foo5
print $sock "deletess 99 foo5\r\n";
like(scalar <$sock>, qr/^NOT_FOUND\s\d*\s*/, "deletess foo");
#getss(get a new lease)
@result = mem_getss($sock, "10000","foo5");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
like(@result[1], qr/^9\d\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];

# delete a lease(delete the lease create the a new lease,
#and the new lease inherit the old lease's expiration time)
print $sock "delete foo\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "delete a lease");
@result = mem_getss($sock, "10000","foo");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
like(@result[1], qr/^9\d\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];

# delete a key not exist (do NOT create a lease)
print $sock "delete foo4\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "delete a key not exist");
@result = mem_getss($sock, "10000","foo4");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
like(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];


#touch
#--------------------
# touch (do nothing to the lease)
print $sock "touch foo 1\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "touch a lease");

sleep(2);

# getss foo (should get the lease)
print $sock "getss foo\r\n";
isnt(scalar <$sock>, "END\r\n", "after touch, lease is not expired");


#stats
#-------------------
# TO DO


# multi-getss
#--------------------------
print $sock "getss foo1 foo2\r\n";
isnt(scalar <$sock>, "END\r\n", "getss two keys");
#getss(get a new lease)
@result = mem_getss($sock, "10000","foo1");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
like(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];
my $foo1_cas=@result[0];
@result = mem_getss($sock, "10000","foo2");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
like(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];
my $foo2_cas=@result[0];
# validate foo1 != foo2
ok($foo1_cas != $foo2_cas, "foo1 != foo2 multi-gets success");

### simulate race condition with getss and deletess, it should create only one lease
#---------------------------

#race condition with getss
print $sock "getss 100 foo3\r\n";
print $sock2 "getss 200 foo3\r\n";
my $res1 = <$sock>.<$sock>.<$sock>;
my $res2 = <$sock2>.<$sock2>.<$sock2>;
isnt($res1,$res2,"the first time and second time to getss a no-exist key, return different");

#getss(get a new lease)
@result = mem_getss($sock, "10000","foo3");
is(@result[0], $identifier1+1, "getss identifier: $identifier1");
unlike(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];
my $foo1_cas=@result[0];

#race condition with deletess
print $sock  "deletess 100 foo3\r\n";
print $sock2 "deletess 100 foo3\r\n";
my $res1 = <$sock>;
my $res2 = <$sock2>;
isnt($res1,$res2,"the first time and second time to deletess a lease, return different");
#getss(get a new lease, the identifier shoud add 2)
@result = mem_getss($sock, "10000","foo3");
is(@result[0], $identifier1+2, "getss identifier: $identifier1");
unlike(@result[1], qr/^0\s*/, "getss  lease remain time:@result[1]");
is(@result[2], $lease_flag, "getss  lease flag: @result[2]");
$identifier1=@result[0];



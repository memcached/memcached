#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use IO::Select;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

my $backend = new_memcached('-l 127.0.0.1', 12221);
my $proxy = new_memcached('-o proxy_config=routelib,proxy_arg=./t/proxynoreply.lua -t 1');
my $client = $proxy->sock;
$client->autoflush(1);
my $readable = IO::Select->new($client);

print $client "set noreply-delete 0 0 3\r\nabc\r\n";
is(scalar <$client>, "STORED\r\n", 'seed key for delete');
print $client "delete noreply-delete noreply\r\n";
ok(!$readable->can_read(0.1), 'delete noreply sends no reply');
print $client "get noreply-delete\r\n";
is(scalar <$client>, "END\r\n", 'delete noreply removed the key');

print $client "set noreply-error 0 0 3\r\nabc\r\n";
is(scalar <$client>, "STORED\r\n", 'seed non-numeric key');
print $client "incr noreply-error 1 noreply\r\n";
ok(!$readable->can_read(0.1), 'backend error on noreply sends no reply');
print $client "get noreply-error\r\n";
is(scalar <$client>, "VALUE noreply-error 0 3\r\n", 'next reply is not a stale error');
is(scalar <$client>, "abc\r\n", 'non-numeric value is unchanged');
is(scalar <$client>, "END\r\n", 'get reply terminates normally');

done_testing();

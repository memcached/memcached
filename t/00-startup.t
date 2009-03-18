#!/usr/bin/perl

use strict;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

eval {
    my $server = new_memcached();
    ok($server, "started the server");
};
is($@, '', 'Basic startup works');

eval {
    my $server = new_memcached("-l fooble");
};
ok($@, "Died with illegal -l args");

eval {
    my $server = new_memcached("-l 127.0.0.1");
};
is($@,'', "-l 127.0.0.1 works");

eval {
    my $server = new_memcached('-C');
    my $stats = mem_stats($server->sock, 'settings');
    is('no', $stats->{'cas_enabled'});
};
is($@, '', "-C works");

eval {
    my $server = new_memcached('-b 8675');
    my $stats = mem_stats($server->sock, 'settings');
    is('8675', $stats->{'tcp_backlog'});
};
is($@, '', "-b works");

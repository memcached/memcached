#!/usr/bin/perl

use strict;
use Test::More skip_all => "Tests not written.";  # tests => 1
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;


#!/usr/bin/perl

use strict;
use Test::More tests => 252;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = new_memcached();
my $sock = $server->sock;

print $sock "stats topkeys\r\n";

is(scalar <$sock>, "ERROR\r\n", "No topkeys without command line option.");

$ENV{"MEMCACHED_TOP_KEYS"} = "100";
$server = new_memcached();
$sock = $server->sock;

print $sock "stats topkeys\r\n";
is(scalar <$sock>, "END\r\n", "No top keys yet.");

# Do some operations

print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
mem_get_is($sock, "foo", "fooval");

sub parse_stats {
    my ($stats) = @_;
    my %ret = ();
    my $key;
    foreach $key (keys %$stats) {
        my %h = split /[,=]/,$stats->{$key};
        $ret{$key} = \%h;
    }
    return \%ret;
}


my $stats = parse_stats(mem_stats($sock, 'topkeys'));

is($stats->{'foo'}->{'cmd_set'}, '1');
is($stats->{'foo'}->{'get_hits'}, '1');

foreach my $key (qw(get_misses incr_hits incr_misses decr_hits decr_misses delete_hits delete_misses evictions)) {
    is($stats->{'foo'}->{$key}, 0, "all stats except cmd_set are zero");
}

print $sock "set foo 0 0 6\r\nfooval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored foo");
print $sock "set bar 0 0 6\r\nbarval\r\n";
is(scalar <$sock>, "STORED\r\n", "stored bar");
mem_get_is($sock, "bar", "barval");

$stats = parse_stats(mem_stats($sock, 'topkeys'));

is($stats->{'foo'}->{'cmd_set'}, '2');
is($stats->{'bar'}->{'cmd_set'}, '1');

print $sock "delete foo\r\n";
is(scalar <$sock>, "DELETED\r\n", "deleted foo");

$stats = parse_stats(mem_stats($sock, 'topkeys'));
is($stats->{'foo'}->{'delete_hits'}, 1);
is($stats->{'foo'}->{'delete_misses'}, 0);
is($stats->{'foo'}->{'cmd_set'}, 2);

#print $sock "delete foo\r\n";
#is(scalar <$sock>, "NOT_FOUND\r\n", "shouldn't delete foo again");

sub check_incr_stats {
    my ($key, $ih, $im, $dh, $dm) = @_;
    my $stats = parse_stats(mem_stats($sock, 'topkeys'));

    is($stats->{$key}->{'incr_hits'}, $ih);
    is($stats->{$key}->{'incr_misses'}, $im);
    is($stats->{$key}->{'decr_hits'}, $dh);
    is($stats->{$key}->{'decr_misses'}, $dm);
}

print $sock "incr i 1\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "shouldn't incr a missing thing");
check_incr_stats("i", 0, 1, 0, 0);

print $sock "decr d 1\r\n";
is(scalar <$sock>, "NOT_FOUND\r\n", "shouldn't decr a missing thing");
check_incr_stats("d", 0, 0, 0, 1);

print $sock "set n 0 0 1\r\n0\r\n";
is(scalar <$sock>, "STORED\r\n", "stored n");

print $sock "incr n 3\r\n";
is(scalar <$sock>, "3\r\n", "incr works");
check_incr_stats("n", 1, 0, 0, 0);

print $sock "decr n 1\r\n";
is(scalar <$sock>, "2\r\n", "decr works");
check_incr_stats("n", 1, 0, 1, 0);

print $sock "decr n 1\r\n";
is(scalar <$sock>, "1\r\n", "decr works");
check_incr_stats("n", 1, 0, 2, 0);

my $i;
# Make sure older keys fall out of the LRU
for ($i = 0; $i < 200; $i++) {
    print $sock "set foo$i 0 0 6\r\nfooval\r\n";
    is(scalar <$sock>, "STORED\r\n", "stored foo$i");
}

$stats = parse_stats(mem_stats($sock, 'topkeys'));
is($stats->{'foo99'}->{'cmd_set'}, undef);
is($stats->{'foo100'}->{'cmd_set'}, 1);
is($stats->{'foo199'}->{'cmd_set'}, 1);

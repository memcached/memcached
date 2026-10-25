#!/usr/bin/env perl

# mcp.dist_ring_hash omodes that match java ketama clients. The expected
# owners were generated with the real client libraries
# (KetamaNodeLocator, DefaultHashAlgorithm.KETAMA_HASH) for the same server
# lists.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use Carp qw(croak);
use MemcachedTest;
use IO::Socket qw(AF_INET SOCK_STREAM);
use IO::Select;

if (!supports_proxy()) {
    plan skip_all => 'proxy not enabled';
    exit 0;
}

# expected server index (0-3) for each key.
my %vectors = (
    # spymemcached 2.12.3, servers localhost:12231-12234
    sh => [
        ["sh/key0", 1], ["sh/key1", 0], ["sh/key2", 1], ["sh/key3", 3],
        ["sh/key4", 2], ["sh/key5", 1], ["sh/key6", 1], ["sh/key7", 2],
        ["sh/key8", 2], ["sh/key9", 1], ["sh/key10", 3], ["sh/key11", 0],
        ["sh/key12", 1], ["sh/key13", 0], ["sh/key14", 0], ["sh/key15", 0],
        ["sh/key16", 3], ["sh/key17", 0], ["sh/key18", 2], ["sh/key19", 3],
        ["sh/key20", 1], ["sh/key21", 3], ["sh/key22", 3], ["sh/key23", 1],
        ["sh/key24", 1], ["sh/key25", 1], ["sh/key26", 1], ["sh/key27", 0],
        ["sh/key28", 0], ["sh/key29", 1], ["sh/key30", 3], ["sh/key31", 0],
    ],
    # spymemcached 2.12.3, servers 127.0.0.1:12231-12234
    si => [
        ["si/key0", 0], ["si/key1", 1], ["si/key2", 2], ["si/key3", 3],
        ["si/key4", 1], ["si/key5", 3], ["si/key6", 2], ["si/key7", 1],
        ["si/key8", 0], ["si/key9", 0], ["si/key10", 0], ["si/key11", 2],
        ["si/key12", 1], ["si/key13", 0], ["si/key14", 3], ["si/key15", 2],
        ["si/key16", 1], ["si/key17", 1], ["si/key18", 0], ["si/key19", 1],
        ["si/key20", 0], ["si/key21", 0], ["si/key22", 0], ["si/key23", 3],
        ["si/key24", 3], ["si/key25", 2], ["si/key26", 3], ["si/key27", 0],
        ["si/key28", 3], ["si/key29", 2], ["si/key30", 2], ["si/key31", 2],
    ],
    # elasticache-java-cluster-client 1.2.2 and 1.2.4, servers 127.0.0.1:12231-12234
    ec => [
        ["ec/key0", 3], ["ec/key1", 3], ["ec/key2", 0], ["ec/key3", 0],
        ["ec/key4", 0], ["ec/key5", 3], ["ec/key6", 1], ["ec/key7", 2],
        ["ec/key8", 1], ["ec/key9", 2], ["ec/key10", 1], ["ec/key11", 2],
        ["ec/key12", 3], ["ec/key13", 0], ["ec/key14", 0], ["ec/key15", 1],
        ["ec/key16", 1], ["ec/key17", 1], ["ec/key18", 2], ["ec/key19", 2],
        ["ec/key20", 3], ["ec/key21", 1], ["ec/key22", 1], ["ec/key23", 0],
        ["ec/key24", 3], ["ec/key25", 1], ["ec/key26", 0], ["ec/key27", 1],
        ["ec/key28", 0], ["ec/key29", 1], ["ec/key30", 3], ["ec/key31", 2],
    ],
    # elasticache-java-cluster-client 1.2.2, servers 10.0.0.1-4:11211
    eh => [
        ["eh/key0", 1], ["eh/key1", 1], ["eh/key2", 0], ["eh/key3", 3],
        ["eh/key4", 1], ["eh/key5", 3], ["eh/key6", 0], ["eh/key7", 3],
        ["eh/key8", 0], ["eh/key9", 2], ["eh/key10", 0], ["eh/key11", 1],
        ["eh/key12", 0], ["eh/key13", 2], ["eh/key14", 1], ["eh/key15", 3],
        ["eh/key16", 0], ["eh/key17", 3], ["eh/key18", 1], ["eh/key19", 1],
        ["eh/key20", 0], ["eh/key21", 0], ["eh/key22", 0], ["eh/key23", 0],
        ["eh/key24", 3], ["eh/key25", 0], ["eh/key26", 0], ["eh/key27", 3],
        ["eh/key28", 3], ["eh/key29", 3], ["eh/key30", 1], ["eh/key31", 1],
    ],
);

my @srv;
for my $port (12231 .. 12234) {
    my $s = IO::Socket->new(
        Domain => AF_INET,
        Type => SOCK_STREAM,
        Proto => 'tcp',
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        ReusePort => 1,
        Listen => 16) || die "IO::Socket: $@";
    push(@srv, $s);
}

my $p_srv = new_memcached('-o proxy_config=./t/proxyring.lua -t 1');
my $ps = $p_srv->sock;
$ps->autoflush(1);

# every pool connects to every server: one connection per pool.
my $pools = supports_tls() ? 4 : 2;
my %server_of; # socket -> server index
my $besel = IO::Select->new();
for my $i (0 .. $#srv) {
    for (1 .. $pools) {
        my $be = $srv[$i]->accept();
        $be->autoflush(1);
        like(<$be>, qr/version/, "server $i: received version command");
        print $be "VERSION 1.0.0-mock
";
        $server_of{$be} = $i;
        $besel->add($be);
    }
}

sub check_owners {
    my $name = shift;
    my $list = $vectors{$name};
    my $ok = 0;
    for my $v (@$list) {
        my ($key, $want) = @$v;
        print $ps "mg $key
";
        my @ready = $besel->can_read(5);
        is(scalar @ready, 1, "$key: sent to one backend");
        my $be = $ready[0];
        is(scalar <$be>, "mg $key
", "$key: backend received the request");
        print $be "EN
";
        is(scalar <$ps>, "EN
", "$key: client received the response");
        $ok++ if $server_of{$be} == $want;
    }
    is($ok, scalar @$list, "$name: every key went to the server the java client picks");
}

subtest 'spymemcached, hostname' => sub { check_owners("sh") };
subtest 'spymemcached, IP address' => sub { check_owners("si") };

SKIP: {
    skip "omode elasticache needs a TLS build", 2 unless supports_tls();
    subtest 'elasticache' => sub { check_owners("ec") };
    subtest 'elasticache, hashkey' => sub { check_owners("eh") };
}

done_testing();

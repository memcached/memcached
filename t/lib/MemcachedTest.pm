package MemcachedTest;
use strict;
use IO::Socket::INET;
use Exporter 'import';
use FindBin qw($Bin);
use Carp qw(croak);
use vars qw(@EXPORT);

@EXPORT = qw(new_memcached sleep mem_get_is mem_stats);

sub sleep {
    my $n = shift;
    select undef, undef, undef, $n;
}

sub mem_stats {
    my ($sock, $type) = @_;
    $type = $type ? " $type" : "";
    print $sock "stats$type\r\n";
    my $stats = {};
    while (<$sock>) {
        last if /^(\.|END)/;
        /^STAT (\S+) (\d+)/;
        #print " slabs: $_";
        $stats->{$1} = $2;
    }
    return $stats;
}

sub mem_get_is {
    # works on single-line values only.  no newlines in value.
    my ($sock_opts, $key, $val, $msg) = @_;
    my $opts = ref $sock_opts eq "HASH" ? $sock_opts : {};
    my $sock = ref $sock_opts eq "HASH" ? $opts->{sock} : $sock_opts;

    my $expect_flags = $opts->{flags} || 0;
    my $dval = defined $val ? "'$val'" : "<undef>";
    $msg ||= "$key == $dval";

    print $sock "get $key\r\n";
    if (! defined $val) {
        my $line = scalar <$sock>;
        if ($line =~ /^VALUE/) {
            $line .= scalar(<$sock>) . scalar(<$sock>);
        }
        Test::More::is($line, "END\r\n", $msg);
    } else {
        my $len = length($val);
        my $body = scalar(<$sock>);
        my $expected = "VALUE $key $expect_flags $len\r\n$val\r\nEND\r\n";
        if (!$body || $body =~ /^END/) {
            Test::More::is($body, $expected, $msg);
            return;
        }
        $body .= scalar(<$sock>) . scalar(<$sock>);
        Test::More::is($body, $expected, $msg);
    }
}

sub free_port {
    my $sock;
    my $port;
    while (!$sock) {
        $port = int(rand(20000)) + 30000;
        $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
                                      LocalPort => $port,
                                      Proto     => 'tcp',
                                      ReuseAddr => 1);
    }
    return $port;
}

sub new_memcached {
    my $args = shift || "";
    my $port = free_port();
    $args .= " -p $port";
    if ($< == 0) {
        $args .= " -u root";
    }
    my $childpid = fork();

    my $exe = "$Bin/../memcached-debug";
    croak("memcached binary doesn't exist.  Haven't run 'make' ?\n") unless -e $exe;
    croak("memcached binary not executable\n") unless -x _;

    unless ($childpid) {
        exec "$exe $args";
        exit; # never gets here.
    }

    for (1..20) {
        my $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
        if ($conn) {
            return Memcached::Handle->new(pid  => $childpid,
                                          conn => $conn,
                                          port => $port);
        }
        select undef, undef, undef, 0.10;
    }
    croak("Failed to startup/connect to memcached server.");

}

############################################################################
package Memcached::Handle;
sub new {
    my ($class, %params) = @_;
    return bless \%params, $class;
}

sub DESTROY {
    my $self = shift;
    kill 9, $self->{pid};
}

sub port { $_[0]{port} }

sub sock {
    my $self = shift;
    return $self->{conn} if $self->{conn} && getpeername($self->{conn});
    return $self->new_sock;
}

sub new_sock {
    my $self = shift;
    return IO::Socket::INET->new(PeerAddr => "127.0.0.1:$self->{port}");
}

1;

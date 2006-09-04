package MemcachedTest;
use strict;
use IO::Socket::INET;
use Exporter 'import';
use FindBin qw($Bin);
use Carp qw(croak);
use vars qw(@EXPORT);

@EXPORT = qw(new_memcached sleep);

sub sleep {
    my $n = shift;
    select undef, undef, undef, $n;
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
    my $childpid = fork();

    my $exe = "$Bin/../memcached";
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

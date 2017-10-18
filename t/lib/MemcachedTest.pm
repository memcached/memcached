package MemcachedTest;
use strict;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Exporter 'import';
use Carp qw(croak);
use vars qw(@EXPORT);

# Instead of doing the substitution with Autoconf, we assume that
# cwd == builddir.
use Cwd;
my $builddir = getcwd;

my @unixsockets = ();

@EXPORT = qw(new_memcached sleep mem_get_is mem_gets mem_gets_is mem_stats
             supports_sasl free_port supports_drop_priv supports_extstore);

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
        /^(STAT|ITEM) (\S+)\s+([^\r\n]+)/;
        #print " slabs: $_";
        $stats->{$2} = $3;
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

sub mem_gets {
    # works on single-line values only.  no newlines in value.
    my ($sock_opts, $key) = @_;
    my $opts = ref $sock_opts eq "HASH" ? $sock_opts : {};
    my $sock = ref $sock_opts eq "HASH" ? $opts->{sock} : $sock_opts;
    my $val;
    my $expect_flags = $opts->{flags} || 0;

    print $sock "gets $key\r\n";
    my $response = <$sock>;
    if ($response =~ /^END/) {
        return "NOT_FOUND";
    }
    else
    {
        $response =~ /VALUE (.*) (\d+) (\d+) (\d+)/;
        my $flags = $2;
        my $len = $3;
        my $identifier = $4;
        read $sock, $val , $len;
        # get the END
        $_ = <$sock>;
        $_ = <$sock>;

        return ($identifier,$val);
    }

}
sub mem_gets_is {
    # works on single-line values only.  no newlines in value.
    my ($sock_opts, $identifier, $key, $val, $msg) = @_;
    my $opts = ref $sock_opts eq "HASH" ? $sock_opts : {};
    my $sock = ref $sock_opts eq "HASH" ? $opts->{sock} : $sock_opts;

    my $expect_flags = $opts->{flags} || 0;
    my $dval = defined $val ? "'$val'" : "<undef>";
    $msg ||= "$key == $dval";

    print $sock "gets $key\r\n";
    if (! defined $val) {
        my $line = scalar <$sock>;
        if ($line =~ /^VALUE/) {
            $line .= scalar(<$sock>) . scalar(<$sock>);
        }
        Test::More::is($line, "END\r\n", $msg);
    } else {
        my $len = length($val);
        my $body = scalar(<$sock>);
        my $expected = "VALUE $key $expect_flags $len $identifier\r\n$val\r\nEND\r\n";
        if (!$body || $body =~ /^END/) {
            Test::More::is($body, $expected, $msg);
            return;
        }
        $body .= scalar(<$sock>) . scalar(<$sock>);
        Test::More::is($body, $expected, $msg);
    }
}

sub free_port {
    my $type = shift || "tcp";
    my $sock;
    my $port;
    while (!$sock) {
        $port = int(rand(20000)) + 30000;
        $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
                                      LocalPort => $port,
                                      Proto     => $type,
                                      ReuseAddr => 1);
    }
    return $port;
}

sub supports_udp {
    my $output = `$builddir/memcached-debug -h`;
    return 0 if $output =~ /^memcached 1\.1\./;
    return 1;
}

sub supports_sasl {
    my $output = `$builddir/memcached-debug -h`;
    return 1 if $output =~ /sasl/i;
    return 0;
}

sub supports_extstore {
    my $output = `$builddir/memcached-debug -h`;
    return 1 if $output =~ /ext_path/i;
    return 0;
}

sub supports_drop_priv {
    my $output = `$builddir/memcached-debug -h`;
    return 1 if $output =~ /no_drop_privileges/i;
    return 0;
}

sub new_memcached {
    my ($args, $passed_port) = @_;
    my $port = $passed_port;
    my $host = '127.0.0.1';

    if ($ENV{T_MEMD_USE_DAEMON}) {
        my ($host, $port) = ($ENV{T_MEMD_USE_DAEMON} =~ m/^([^:]+):(\d+)$/);
        my $conn = IO::Socket::INET->new(PeerAddr => "$host:$port");
        if ($conn) {
            return Memcached::Handle->new(conn => $conn,
                                          host => $host,
                                          port => $port);
        }
        croak("Failed to connect to specified memcached server.") unless $conn;
    }

    if ($< == 0) {
        $args .= " -u root";
    }
    $args .= " -o relaxed_privileges";

    my $udpport;
    if ($args =~ /-l (\S+)/) {
        $port = free_port();
        $udpport = free_port("udp");
        $args .= " -p $port";
        if (supports_udp()) {
            $args .= " -U $udpport";
        }
    } elsif ($args !~ /-s (\S+)/) {
        my $num = @unixsockets;
        my $file = "/tmp/memcachetest.$$.$num";
        $args .= " -s $file";
        push(@unixsockets, $file);
    }

    my $childpid = fork();

    my $exe = "$builddir/memcached-debug";
    croak("memcached binary doesn't exist.  Haven't run 'make' ?\n") unless -e $exe;
    croak("memcached binary not executable\n") unless -x _;

    unless ($childpid) {
        exec "$builddir/timedrun 600 $exe $args";
        exit; # never gets here.
    }

    # unix domain sockets
    if ($args =~ /-s (\S+)/) {
        sleep 1;
        my $filename = $1;
        my $conn = IO::Socket::UNIX->new(Peer => $filename) ||
            croak("Failed to connect to unix domain socket: $! '$filename'");

        return Memcached::Handle->new(pid  => $childpid,
                                      conn => $conn,
                                      domainsocket => $filename,
                                      host => $host,
                                      port => $port);
    }

    # try to connect / find open port, only if we're not using unix domain
    # sockets

    for (1..20) {
        my $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
        if ($conn) {
            return Memcached::Handle->new(pid  => $childpid,
                                          conn => $conn,
                                          udpport => $udpport,
                                          host => $host,
                                          port => $port);
        }
        select undef, undef, undef, 0.10;
    }
    croak("Failed to startup/connect to memcached server.");
}

END {
    for (@unixsockets) {
        unlink $_;
    }
}

############################################################################
package Memcached::Handle;
sub new {
    my ($class, %params) = @_;
    return bless \%params, $class;
}

sub DESTROY {
    my $self = shift;
    kill 2, $self->{pid};
}

sub stop {
    my $self = shift;
    kill 15, $self->{pid};
}

sub host { $_[0]{host} }
sub port { $_[0]{port} }
sub udpport { $_[0]{udpport} }

sub sock {
    my $self = shift;

    if ($self->{conn} && ($self->{domainsocket} || getpeername($self->{conn}))) {
        return $self->{conn};
    }
    return $self->new_sock;
}

sub new_sock {
    my $self = shift;
    if ($self->{domainsocket}) {
        return IO::Socket::UNIX->new(Peer => $self->{domainsocket});
    } else {
        return IO::Socket::INET->new(PeerAddr => "$self->{host}:$self->{port}");
    }
}

sub new_udp_sock {
    my $self = shift;
    return IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                 PeerPort => $self->{udpport},
                                 Proto    => 'udp',
                                 LocalAddr => '127.0.0.1',
                                 LocalPort => MemcachedTest::free_port('udp'),
        );

}

1;

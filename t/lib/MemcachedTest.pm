package MemcachedTest;
use strict;
use IO::Socket::INET;
use IO::Socket::UNIX;
use POSIX ":sys_wait_h";
use Exporter 'import';
use Carp qw(croak);
use vars qw(@EXPORT);

# Instead of doing the substitution with Autoconf, we assume that
# cwd == builddir.
use Cwd;
my $builddir = getcwd;

my @unixsockets = ();

@EXPORT = qw(new_memcached sleep
             mem_get_is mem_gets mem_gets_is mem_stats mem_move_time
             supports_sasl free_port supports_drop_priv supports_extstore
             wait_ext_flush supports_tls enabled_tls_testing run_help
             supports_unix_socket get_memcached_exe supports_proxy);

use constant MAX_READ_WRITE_SIZE => 16384;
use constant SRV_CRT => "server_crt.pem";
use constant SRV_KEY => "server_key.pem";
use constant CLIENT_CRT => "client_crt.pem";
use constant CLIENT_KEY => "client_key.pem";
use constant CA_CRT => "cacert.pem";

my $testdir = $builddir . "/t/";
my $client_crt = $testdir. CLIENT_CRT;
my $client_key = $testdir. CLIENT_KEY;
my $server_crt = $testdir . SRV_CRT;
my $server_key = $testdir . SRV_KEY;

my $tls_checked = 0;

sub sleep {
    my $n = shift;
    select undef, undef, undef, $n;
}

# Wait until all items have flushed
sub wait_ext_flush {
    my $sock = shift;
    my $target = shift || 0;
    my $sum = $target + 1;
    while ($sum > $target) {
        my $s = mem_stats($sock, "items");
        $sum = 0;
        for my $key (keys %$s) {
            if ($key =~ m/items:(\d+):number/) {
                # Ignore classes which can contain extstore items
                next if $1 < 3;
                $sum += $s->{$key};
            }
        }
        sleep 1 if $sum > $target;
    }
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

sub mem_move_time {
    my ($sock, $move) = @_;
    print $sock "debugtime $move\r\n";
    <$sock>;
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
        if (enabled_tls_testing()) {
            $sock = eval qq{ IO::Socket::SSL->new(LocalAddr => '127.0.0.1',
                                      LocalPort => $port,
                                      Proto     => '$type',
                                      ReuseAddr => 1,
                                      SSL_verify_mode => SSL_VERIFY_NONE);
                                      };
             die $@ if $@; # sanity check.
        } else {
            $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
                                      LocalPort => $port,
                                      Proto     => $type,
                                      ReuseAddr => 1);
        }
    }
    return $port;
}

sub print_help {
    my $exe = get_memcached_exe();
    my $output = `$exe -h`;
    return $output;
}

sub supports_udp {
    my $output = print_help();
    return 0 if $output =~ /^memcached 1\.1\./;
    return 1;
}

sub supports_sasl {
    my $output = print_help();
    return 1 if $output =~ /sasl/i;
    return 0;
}

sub supports_extstore {
    my $output = print_help();
    return 1 if $output =~ /ext_path/i;
    return 0;
}

sub supports_proxy {
    my $output = print_help();
    return 1 if $output =~ /proxy_config/i;
    return 0;
}

sub supports_tls {
    my $output = print_help();
    return 1 if $output =~ /enable-ssl/i;
    return 0;
}

sub supports_unix_socket {
    my $output = print_help();
    return 1 if $output =~ /unix-socket/i;
    return 0;
}

sub enabled_tls_testing {
    if ($tls_checked) {
        return 1;
    } elsif (supports_tls() && $ENV{SSL_TEST}) {
        eval "use IO::Socket::SSL";
        croak("IO::Socket::SSL not installed or failed to load, cannot run SSL tests as requested") if $@;
        $tls_checked = 1;
        return 1;
    }
}

sub supports_drop_priv {
    my $output = print_help();
    return 1 if $output =~ /no_drop_privileges/i;
    return 0;
}

sub get_memcached_exe {
    my $exe = "$builddir/memcached-debug";
    croak("memcached binary doesn't exist.  Haven't run 'make' ?\n") unless -e $exe;
    croak("memcached binary not executable\n") unless -x _;
    return $exe;
}

sub run_help {
    my $exe = get_memcached_exe();
    return system("$exe -h");
}

# -1 if the pid is actually dead.
sub is_running {
    return waitpid($_[0], WNOHANG) >= 0 ? 1 : 0;
}

sub new_memcached {
    my ($args, $passed_port) = @_;
    my $port = $passed_port;
    my $host = '127.0.0.1';
    my $ssl_enabled  = enabled_tls_testing();
    my $unix_socket_disabled  = !supports_unix_socket();

    if ($ENV{T_MEMD_USE_DAEMON}) {
        my ($host, $port) = ($ENV{T_MEMD_USE_DAEMON} =~ m/^([^:]+):(\d+)$/);
        my $conn;
        if ($ssl_enabled) {
            $conn = eval qq{IO::Socket::SSL->new(PeerAddr => "$host:$port",
                                        SSL_verify_mode => SSL_VERIFY_NONE,
                                        SSL_cert_file => '$client_crt',
                                        SSL_key_file => '$client_key');
                                        };
             die $@ if $@; # sanity check.
        } else {
            $conn = IO::Socket::INET->new(PeerAddr => "$host:$port");
        }
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
    if ($args =~ /-l (\S+)/ || (($ssl_enabled || $unix_socket_disabled) && ($args !~ /-s (\S+)/))) {
        if (!$port) {
            $port = free_port();
        }
        $udpport = free_port("udp");
        $args .= " -p $port";
        if (supports_udp() && $args !~ /-U (\S+)/) {
            $args .= " -U $udpport";
        }
        if ($ssl_enabled) {
            $args .= " -Z";
            if ($args !~ /-o ssl_chain_cert=(\S+)/) {
                $args .= " -o ssl_chain_cert=$server_crt";
            }
            if ($args !~ /-o ssl_key=(\S+)/) {
                $args .= " -o ssl_key=$server_key";
            }
        }
    } elsif ($args !~ /-s (\S+)/) {
        my $num = @unixsockets;
        my $file = "/tmp/memcachetest.$$.$num";
        $args .= " -s $file";
        push(@unixsockets, $file);
    }

    my $childpid = fork();

    my $exe = get_memcached_exe();

    unless ($childpid) {
        my $valgrind = "";
        my $valgrind_args = "--quiet --error-exitcode=1 --exit-on-first-error=yes";
        if ($ENV{VALGRIND_ARGS}) {
            $valgrind_args = $ENV{VALGRIND_ARGS};
        }
        if ($ENV{VALGRIND_TEST}) {
            $valgrind = "valgrind $valgrind_args";
            # NOTE: caller file stuff.
            $valgrind .= " $ENV{VALGRIND_EXTRA_ARGS}";
        }
        my $cmd = "$builddir/timedrun 600 $valgrind $exe $args";
        #print STDERR "RUN: $cmd\n\n";
        exec $cmd;
        exit; # never gets here.
    }

    # unix domain sockets
    if ($args =~ /-s (\S+)/) {
        # A slow/emulated/valgrinded/etc system may take longer than a second
        # for the unix socket to appear.
        my $filename = $1;
        for (1..20) {
            sleep 1;
            my $conn = IO::Socket::UNIX->new(Peer => $filename);

            if ($conn) {
                return Memcached::Handle->new(pid  => $childpid,
                                              conn => $conn,
                                              domainsocket => $filename,
                                              host => $host,
                                              port => $port);
            } else {
                croak("Failed to connect to unix socket: memcached not running") unless is_running($childpid);
                sleep 1;
            }
        }
        croak("Failed to connect to unix domain socket: $! '$filename'") if $@;
    }

    # try to connect / find open port, only if we're not using unix domain
    # sockets

    for (1..80) {
        my $conn;
        if ($ssl_enabled) {
            $conn = eval qq{ IO::Socket::SSL->new(PeerAddr => "127.0.0.1:$port",
                                        SSL_verify_mode => SSL_VERIFY_NONE,
                                        SSL_cert_file => '$client_crt',
                                        SSL_key_file => '$client_key');
                                        };
            die $@ if $@; # sanity check.
        } else {
            $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
        }
        if ($conn) {
            return Memcached::Handle->new(pid  => $childpid,
                                          conn => $conn,
                                          udpport => $udpport,
                                          host => $host,
                                          port => $port);
        }
        croak("Failed to connect: memcached not running") unless is_running($childpid);
        select undef, undef, undef, 0.25;
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
use POSIX ":sys_wait_h";
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

sub graceful_stop {
    my $self = shift;
    kill 'SIGUSR1', $self->{pid};
}

# -1 if the pid is actually dead.
sub is_running {
    my $self = shift;
    return waitpid($self->{pid}, WNOHANG) >= 0 ? 1 : 0;
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
    } elsif (MemcachedTest::enabled_tls_testing()) {
        my $ssl_session_cache = shift;
        my $ssl_version = shift;
        return eval qq{ IO::Socket::SSL->new(PeerAddr => "$self->{host}:$self->{port}",
                                    SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
                                    SSL_session_cache => \$ssl_session_cache,
                                    SSL_version => '$ssl_version',
                                    SSL_cert_file => '$client_crt',
                                    SSL_key_file => '$client_key');
                                    };
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

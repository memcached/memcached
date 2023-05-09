#!/usr/bin/env perl

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

# Set up some server sockets.
sub mock_server {
    my $port = shift;
    my $srv = IO::Socket->new(
        Domain => AF_INET,
        Type => SOCK_STREAM,
        Proto => 'tcp',
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        ReusePort => 1,
        Listen => 5) || die "IO::Socket: $@";
    return $srv;
}

# Accept and validate a new backend connection.
sub accept_backend {
    my $srv = shift;
    my $be = $srv->accept();
    $be->autoflush(1);
    ok(defined $be, "mock backend created");
    like(<$be>, qr/version/, "received version command");
    print $be "VERSION 1.0.0-mock\r\n";

    return $be;
}

note("Initialization:" . __LINE__);

my @mocksrvs = ();
#diag "making mock servers";
for my $port (11411, 11412, 11413) {
    my $srv = mock_server($port);
    ok(defined $srv, "mock server created");
    push(@mocksrvs, $srv);
}

my $p_srv = new_memcached('-o proxy_config=./t/proxyunits.lua');
my $ps = $p_srv->sock;
$ps->autoflush(1);

# set up server backend sockets.
my @mbe = ();
#diag "accepting mock backends";
for my $msrv (@mocksrvs) {
    my $be = accept_backend($msrv);
    push(@mbe, $be);
}

# Put a version command down the pipe to ensure the socket is clear.
# client version commands skip the proxy code
sub check_version {
    my $ps = shift;
    print $ps "version\r\n";
    like(<$ps>, qr/VERSION /, "version received");
}

# Send a touch command to all backends, and verify response.
# This makes sure socket buffers are clean between tests.
sub check_sanity {
    my $ps = shift;
    my $cmd = "touch /sanity/a 50\r\n";
    print $ps $cmd;
    foreach my $be (@mbe) {
        is(scalar <$be>, $cmd, "sanity check: touch cmd received");
        print $be "TOUCHED\r\n";
    }
    is(scalar <$ps>, "TOUCHED\r\n", "sanity check: TOUCHED response received.");
}

# $ps_send : request to proxy
# $be_recv : ref to a hashmap from be index to an array of received requests for validation.
# $be_send : ref to a hashmap from be index to an array of responses to proxy.
# $ps_recv : ref to response returned by proxy
# backends in $be_recv and $be_send are vistied by looping through the @mbe.
sub proxy_test {
    my %args = @_;

    my $ps_send = $args{ps_send};
    my $be_recv = $args{be_recv} // {};
    my $be_send = $args{be_send} // {};
    my $ps_recv = $args{ps_recv} // [];

    # sends request to proxy
    print $ps $ps_send;

    # verify all backends received request
    foreach my $idx (keys @mbe) {
        if (exists $be_recv->{$idx}) {
            my $be = $mbe[$idx];
            foreach my $recv (@{$be_recv->{$idx}}) {
                is(scalar <$be>, $recv, "be " . $idx . " received expected response");
            }
        }
    }

    # backends send responses
    foreach my $idx (keys @mbe) {
        if (exists $be_send->{$idx}) {
            my $be = $mbe[$idx];
            foreach my $send (@{$be_send->{$idx}}) {
                print $be $send;
            }
        }
    }

    # verify proxy received response
    if (scalar @{$ps_recv}) {
        foreach my $recv (@{$ps_recv}) {
            is(scalar <$ps>, $recv, "ps returned expected response.");
        }
    } else {
        # makes sure nothing was received when ps_recv is empty.
        check_version($ps)
    }
}

{
    # Write a request with bad syntax, and check the response.
    print $ps "set with the wrong number of tokens\n";
    is(scalar <$ps>, "CLIENT_ERROR parsing request\r\n", "got CLIENT_ERROR for bad syntax");
}

# Basic test with a backend; write a request to the client socket, read it
# from a backend socket, and write a response to the backend socket.
#
# The array @mbe holds references to our sockets for the backends listening on
# the above mocked servers. In most tests we're only routing to the first
# backend in the list ($mbe[0])
#
# In this case the client will receive an error and the backend gets closed,
# so we have to re-establish it.
{
    note("Test missing END:" . __LINE__);

    # Test a fix for passing through partial read data if END ends up missing.
    my $be = $mbe[0];
    my $w = $p_srv->new_sock;
    print $w "watch proxyevents\n";
    is(<$w>, "OK\r\n", "watcher enabled");

    # write a request to proxy.
    print $ps "get /b/a\r\n";

    # verify request is received by backend.
    is(scalar <$be>, "get /b/a\r\n", "get passthrough");

    # write a response with partial data.
    print $be "VALUE /b/a 0 2\r\nhi\r\nEN";

    # verify the error response from proxy
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "backend failure error");

    # verify a particular proxy event logline is received
    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_backend error=timeout name=127.0.0.1 port=\d+ depth=1 rbuf=EN/, "got backend error log line");

    # backend is disconnected due to the error, so we have to re-establish it.
    $mbe[0] = accept_backend($mocksrvs[0]);
}

# This test is similar to the above one, except we also establish a watcher to
# check for appropriate log entries.
{
    note("Test trailingdata:" . __LINE__);

    # Test a log line with detailed data from backend failures.
    my $be = $mbe[0];
    my $w = $p_srv->new_sock;
    print $w "watch proxyevents\n";
    is(<$w>, "OK\r\n", "watcher enabled");

    print $ps "get /b/c\r\n";
    is(scalar <$be>, "get /b/c\r\n", "get passthrough");
    # Set off a "trailing data" error
    print $be "VALUE /b/c 0 2\r\nok\r\nEND\r\ngarbage";

    is(scalar <$ps>, "VALUE /b/c 0 2\r\n", "got value back");
    is(scalar <$ps>, "ok\r\n", "got data back");
    is(scalar <$ps>, "END\r\n", "got end string");

    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_backend error=trailingdata name=127.0.0.1 port=\d+ depth=0 rbuf=garbage/, "got backend error log line");

    $mbe[0] = accept_backend($mocksrvs[0]);
}

note("Test bugfix for missingend:" . __LINE__);

# This is an example of a test which will only pass before a bugfix is issued.
# It's good practice where possible to write a failing test, then check it
# against a code fix. We then leave the test in the file for reference.
# Though noting when it was fixed is probably better than what I did here :)
SKIP: {
    skip "Remove this skip line to demonstrate pre-patch bug", 1;
    # Test issue with finding response complete when read lands between value
    # size and value + response line in size.
    my $be = $mbe[0];
    my $w = $p_srv->new_sock;
    print $w "watch proxyevents\n";
    is(<$w>, "OK\r\n", "watcher enabled");

    print $ps "get /b/c\r\n";
    is(scalar <$be>, "get /b/c\r\n", "get passthrough");

    # Set off a "missingend" error.
    # The server will wake up several times, thinking it has read the
    # full size of response but it only read enough for the value portion.
    print $be "VALUE /b/c 0 5\r\nhe";
    sleep 0.1;
    print $be "llo";
    sleep 0.1;
    print $be "\r\nEND\r\n";

    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n");

    like(<$w>, qr/ts=(\S+) gid=\d+ type=proxy_backend error=missingend name=127.0.0.1 port=\d+ depth=1 rbuf=/, "got missingend error log line");

    $mbe[0] = accept_backend($mocksrvs[0]);
}

{
    # Test issue with finding response complete when read lands between value
    # size and value + response line in size.
    my $be = $mbe[0];

    print $ps "get /b/c\r\n";
    is(scalar <$be>, "get /b/c\r\n", "get passthrough");

    # Set off a "missingend" error.
    # The server will wake up several times, thinking it has read the
    # full size of response but it only read enough for the value portion.
    print $be "VALUE /b/c 0 5\r\nhe";
    sleep 0.1;
    print $be "llo";
    sleep 0.1;
    print $be "\r\nEND\r\n";

    is(scalar <$ps>, "VALUE /b/c 0 5\r\n", "got value back");
    is(scalar <$ps>, "hello\r\n", "got data back");
    is(scalar <$ps>, "END\r\n", "got end string");
}

#diag "ready for main tests";
# Target a single backend, validating basic syntax.
# Should test all command types.
# uses /b/ path for "basic"
{
    note("Test all commands to a single backend:" . __LINE__);

    # Test invalid route.
    print $ps "set /invalid/a 0 0 2\r\nhi\r\n";
    is(scalar <$ps>, "SERVER_ERROR no set route\r\n");

    # Testing against just one backend. Results should make sense despite our
    # invalid request above.
    my $be = $mbe[0];
    my $cmd;

    # TODO: add more tests for the varying response codes.

    # Basic set.
    $cmd = "set /b/a 0 0 2";
    print $ps "$cmd\r\nhi\r\n";
    is(scalar <$be>, "$cmd\r\n", "set passthrough");
    is(scalar <$be>, "hi\r\n", "set value");
    print $be "STORED\r\n";

    is(scalar <$ps>, "STORED\r\n", "got STORED from set");

    # Basic get
    $cmd = "get /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "get passthrough");
    print $be "VALUE /b/a 0 2\r\nhi\r\nEND\r\n";

    is(scalar <$ps>, "VALUE /b/a 0 2\r\n", "get rline");
    is(scalar <$ps>, "hi\r\n", "get data");
    is(scalar <$ps>, "END\r\n", "get end");

    # touch
    $cmd = "touch /b/a 50\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "touch passthrough");
    print $be "TOUCHED\r\n";

    is(scalar <$ps>, "TOUCHED\r\n", "got touch response");

    # gets
    $cmd = "gets /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "gets passthrough");
    print $be "VALUE /b/a 0 2 2\r\nhi\r\nEND\r\n";

    is(scalar <$ps>, "VALUE /b/a 0 2 2\r\n", "gets rline");
    is(scalar <$ps>, "hi\r\n", "gets data");
    is(scalar <$ps>, "END\r\n", "gets end");

    # gat
    $cmd = "gat 10 /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "gat passthrough");
    print $be "VALUE /b/a 0 2\r\nhi\r\nEND\r\n";

    is(scalar <$ps>, "VALUE /b/a 0 2\r\n", "gat rline");
    is(scalar <$ps>, "hi\r\n", "gat data");
    is(scalar <$ps>, "END\r\n", "gat end");

    # gats
    $cmd = "gats 11 /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "gats passthrough");
    print $be "VALUE /b/a 0 2 1\r\nhi\r\nEND\r\n";

    is(scalar <$ps>, "VALUE /b/a 0 2 1\r\n", "gats rline");
    is(scalar <$ps>, "hi\r\n", "gats data");
    is(scalar <$ps>, "END\r\n", "gats end");

    # cas
    $cmd = "cas /b/a 0 0 2 5";
    print $ps "$cmd\r\nhi\r\n";
    is(scalar <$be>, "$cmd\r\n", "cas passthrough");
    is(scalar <$be>, "hi\r\n", "cas value");
    print $be "STORED\r\n";

    is(scalar <$ps>, "STORED\r\n", "got STORED from cas");

    # add
    $cmd = "add /b/a 0 0 2";
    print $ps "$cmd\r\nhi\r\n";
    is(scalar <$be>, "$cmd\r\n", "add passthrough");
    is(scalar <$be>, "hi\r\n", "add value");
    print $be "STORED\r\n";

    is(scalar <$ps>, "STORED\r\n", "got STORED from add");

    # delete
    $cmd = "delete /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "delete passthrough");
    print $be "DELETED\r\n";

    is(scalar <$ps>, "DELETED\r\n", "got delete response");

    # incr
    $cmd = "incr /b/a 1\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "incr passthrough");
    print $be "2\r\n";

    is(scalar <$ps>, "2\r\n", "got incr response");

    # decr
    $cmd = "decr /b/a 1\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "decr passthrough");
    print $be "10\r\n";

    is(scalar <$ps>, "10\r\n", "got decr response");

    # append
    $cmd = "append /b/a 0 0 2";
    print $ps "$cmd\r\nhi\r\n";
    is(scalar <$be>, "$cmd\r\n", "append passthrough");
    is(scalar <$be>, "hi\r\n", "append value");
    print $be "STORED\r\n";

    is(scalar <$ps>, "STORED\r\n", "got STORED from append");

    # prepend
    $cmd = "prepend /b/a 0 0 2";
    print $ps "$cmd\r\nhi\r\n";
    is(scalar <$be>, "$cmd\r\n", "prepend passthrough");
    is(scalar <$be>, "hi\r\n", "prepend value");
    print $be "STORED\r\n";

    is(scalar <$ps>, "STORED\r\n", "got STORED from prepend");

    # [meta commands]
    # testing the bare meta commands.
    # TODO: add more tests for tokens and changing response codes.
    # mg
    $cmd = "mg /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "mg passthrough");
    print $be "HD\r\n";

    is(scalar <$ps>, "HD\r\n", "got mg response");
    # ms
    $cmd = "ms /b/a 2";
    print $ps "$cmd\r\nhi\r\n";
    is(scalar <$be>, "$cmd\r\n", "ms passthrough");
    is(scalar <$be>, "hi\r\n", "ms value");
    print $be "HD\r\n";

    is(scalar <$ps>, "HD\r\n", "got HD from ms");

    # md
    $cmd = "md /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "md passthrough");
    print $be "HD\r\n";

    is(scalar <$ps>, "HD\r\n", "got HD from md");
    # ma
    $cmd = "ma /b/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "ma passthrough");
    print $be "HD\r\n";

    is(scalar <$ps>, "HD\r\n", "got HD from ma");
    # mn?
    # me?
}

# run a cleanser check between each set of tests.
# This ensures nothing was left in the client pipeline.
check_sanity($ps);

{
    note("Test multiget:" . __LINE__);

    # multiget syntax
    # - gets broken into individual gets on backend
    my $be = $mbe[0];
    my $cmd = "get /b/a /b/b /b/c\r\n";
    print $ps $cmd;
    is(scalar <$be>, "get /b/a\r\n", "multiget breakdown a");
    is(scalar <$be>, "get /b/b\r\n", "multiget breakdown b");
    is(scalar <$be>, "get /b/c\r\n", "multiget breakdown c");

    print $be "VALUE /b/a 0 1\r\na\r\n",
              "END\r\n",
              "VALUE /b/b 0 1\r\nb\r\n",
              "END\r\n",
              "VALUE /b/c 0 1\r\nc\r\n",
              "END\r\n";

    for my $key ('a', 'b', 'c') {
        is(scalar <$ps>, "VALUE /b/$key 0 1\r\n", "multiget res $key");
        is(scalar <$ps>, "$key\r\n", "multiget value $key");
    }
    is(scalar <$ps>, "END\r\n", "final END from multiget");

    # Test multiget workaround with misses (known bug)
    print $ps $cmd;
    is(scalar <$be>, "get /b/a\r\n", "multiget breakdown a");
    is(scalar <$be>, "get /b/b\r\n", "multiget breakdown b");
    is(scalar <$be>, "get /b/c\r\n", "multiget breakdown c");

    print $be "END\r\nEND\r\nEND\r\n";
    is(scalar <$ps>, "END\r\n", "final END from multiget");

    # If bugged, the backend will have closed.
    print $ps "get /b/a\r\n";
    is(scalar <$be>, "get /b/a\r\n", "get works after empty multiget");
    print $be "END\r\n";
    is(scalar <$ps>, "END\r\n", "end after empty multiget");
}

check_sanity($ps);

{
    note("Test noreply:" . __LINE__);

    # noreply tests.
    # - backend should receive with noreply/q stripped or mangled
    # - backend should reply as normal
    # - frontend should get nothing; to test issue another command and ensure
    # it only gets that response.
    my $be = $mbe[0];
    my $cmd = "set /b/a 0 0 2 noreply\r\nhi\r\n";
    print $ps $cmd;
    is(scalar <$be>, "set /b/a 0 0 2 noreplY\r\n", "set received with broken noreply");
    is(scalar <$be>, "hi\r\n", "set payload received");

    print $be "STORED\r\n";

    # To ensure success, make another req and ensure res isn't STORED
    $cmd = "touch /b/a 50\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "canary touch received");
    print $be "TOUCHED\r\n";

    is(scalar <$ps>, "TOUCHED\r\n", "got TOUCHED instread of STORED");
}

check_sanity($ps);

{
    subtest 'quiet flag: HD response' => sub {
        # be_recv must receive a response with quiet flag replaced by a space.
        # ps_recv must not receoved HD response.
        proxy_test(
            ps_send => "ms /b/a 2 q\r\nhi\r\n",
            be_recv => {0 => ["ms /b/a 2  \r\n", "hi\r\n"]},
            be_send => {0 => ["HD\r\n"]},
        );
    };

    subtest 'quiet flag: EX response' => sub {
        # be_recv must receive a response with quiet flag replaced by a space.
        # ps_recv must return EX response from the backend.
        proxy_test(
            ps_send => "ms /b/a 2 q\r\nhi\r\n",
            be_recv => {0 => ["ms /b/a 2  \r\n", "hi\r\n"]},
            be_send => {0 => ["EX\r\n"]},
            ps_recv => ["EX\r\n"],
        );
    };

    subtest 'quiet flag: backend failure' => sub {
        # be_recv must receive a response with quiet flag replaced by a space.
        # ps_recv must return backend failure response from the backend.
        proxy_test(
            ps_send => "ms /b/a 2 q\r\nhi\r\n",
            be_recv => {0 => ["ms /b/a 2  \r\n", "hi\r\n"]},
            be_send => {0 => ["garbage\r\n"]},
            ps_recv => ["SERVER_ERROR backend failure\r\n"],
        );
        $mbe[0] = accept_backend($mocksrvs[0]);
    };
}

check_sanity($ps);

# Test Lua request API
{
    note("Test Lua request APIs:" . __LINE__);

    my $be = $mbe[0];

    # fetching the key.
    print $ps "get /getkey/testkey\r\n";
    # look for the key to be slightly different to ensure we hit lua.
    is(scalar <$ps>, "VALUE |/getkey/testkey 0 2\r\n", "request:key()");
    is(scalar <$ps>, "ts\r\n", "request:key() value");
    is(scalar <$ps>, "END\r\n", "request:key() END");

    # rtrimkey
    # this overwrites part of the key with spaces, which should be skipped by
    # a valid protocol parser.
    print $ps "get /rtrimkey/onehalf\r\n";
    is(scalar <$be>, "get /rtrimkey/one    \r\n", "request:rtrimkey()");
    print $be "END\r\n";
    is(scalar <$ps>, "END\r\n", "rtrimkey END");

    # ltrimkey
    print $ps "get /ltrimkey/test\r\n";
    is(scalar <$be>, "get           test\r\n", "request:ltrimkey()");
    print $be "END\r\n";
    is(scalar <$ps>, "END\r\n", "ltrimkey END");

    subtest 'request:ntokens()' => sub {
        # ps_recv must return value that matches the number of tokens.
        proxy_test(
            ps_send => "mg /ntokens/test c v\r\n",
            ps_recv => ["VA 1 C123 v\r\n", "4\r\n"],
        );
    };

    subtest 'request:token() replacement' => sub {
        # be_recv must received a response with replaced CAS token.
        proxy_test(
            ps_send => "ms /token/replacement 2 C123\r\nhi\r\n",
            be_recv => {0 => ["ms /token/replacement 2 C456\r\n", "hi\r\n"]},
            be_send => {0 => ["NF\r\n"]},
            ps_recv => ["NF\r\n"],
        );
    };

    subtest 'request:token() remove' => sub {
        # be_recv must received a response with CAS token removed.
        proxy_test(
            ps_send => "ms /token/removal 2 C123\r\nhi\r\n",
            be_recv => {0 => ["ms /token/removal 2 \r\n", "hi\r\n"]},
            be_send => {0 => ["NF\r\n"]},
            ps_recv => ["NF\r\n"],
        );
    };

    subtest 'request:token() fetch' => sub {
        # be_recv must received the key token in the P flag.
        proxy_test(
            ps_send => "ms /token/fetch 2 C123 P\r\nhi\r\n",
            be_recv => {0 => ["ms /token/fetch 2 C123 P/token/fetch\r\n", "hi\r\n"]},
            be_send => {0 => ["HD\r\n"]},
            ps_recv => ["HD\r\n"],
        );
    };

    # # command() integer

    subtest 'request:has_flag() meta positive 1' => sub {
        # ps_recv must receive HD C123 for a successful hash_flag call.
        proxy_test(
            ps_send => "mg /hasflag/test c\r\n",
            ps_recv => ["HD C123\r\n"],
        );
    };

    subtest 'request:has_flag() meta positive 2' => sub {
        # ps_recv must receive HD Oabc for a successful hash_flag call.
        proxy_test(
            ps_send => "mg /hasflag/test Oabc T999\r\n",
            ps_recv => ["HD Oabc\r\n"],
        );
    };

    subtest 'request:has_flag() meta negative' => sub {
        # ps_recv must receive NF when has_flag returns false.
        proxy_test(
            ps_send => "mg /hasflag/test T999\r\n",
            ps_recv => ["NF\r\n"],
        );
    };

    subtest 'request:has_flag() none-meta ' => sub {
        # ps_recv must receive END for a successful hash_flag call.
        proxy_test(
            ps_send => "get /hasflag/test\r\n",
            ps_recv => ["END\r\n"],
        );
    };

    subtest 'request:flag_token()' => sub {
        # be_recv must receive expected flags after a series of flag_token() calls.
        proxy_test(
            ps_send => "mg /flagtoken/a N10 k c R10\r\n",
            ps_recv => ["HD\r\n"],
        );
    };


    subtest 'request edit' => sub {
        # be_recv must receive the edited request.
        proxy_test(
            ps_send => "ms /request/edit 2\r\nhi\r\n",
            be_recv => {0 => ["ms /request/edit 2\r\n", "ab\r\n"]},
            be_send => {0 => ["HD\r\n"]},
            ps_recv => ["HD\r\n"],
        );
    };

    subtest 'request new' => sub {
        # be_recv must receive the new request.
        proxy_test(
            ps_send => "mg /request/old\r\n",
            be_recv => {0 => ["mg /request/new c\r\n"]},
            be_send => {0 => ["HD C123\r\n"]},
            ps_recv => ["HD C123\r\n"],
        );
    };

    subtest 'request clone response' => sub {
        # be must receive cloned meta-set from the previous meta-get.
        my $be = $mbe[0];
        print $ps "mg /request/clone v\r\n";
        is(scalar <$be>, "mg /request/clone v\r\n", "get passthrough");
        print $be "VA 1 v\r\n4\r\n";
        is(scalar <$be>, "ms /request/a 1\r\n", "received cloned meta-set");
        is(scalar <$be>, "4\r\n", "received cloned meta-set value");
        print $be "HD\r\n";
        is(scalar <$ps>, "HD\r\n", "received HD");
    };
}

check_sanity($ps);
# Test Lua response API
#{
    # elapsed()
    # ok()
    # hit()
    # vlen()
    # code()
    # line()
#}

# Test requests land in proper backend in basic scenarios
{
    note("Test routing by zone:" . __LINE__);

    # TODO: maybe should send values to ensure the right response?
    # I don't think this test is very useful though; probably better to try
    # harder when testing error conditions.
    for my $tu (['a', $mbe[0]], ['b', $mbe[1]], ['c', $mbe[2]]) {
        my $be = $tu->[1];
        my $cmd = "get /zonetest/" . $tu->[0] . "\r\n";
        print $ps $cmd;
        is(scalar <$be>, $cmd, "routed proper zone: " . $tu->[0]);
        print $be "END\r\n";
        is(scalar <$ps>, "END\r\n", "end from zone fetch");
    }
    my $cmd = "get /zonetest/invalid\r\n";
    print $ps $cmd;
    is(scalar <$ps>, "END\r\n", "END from invalid route");
}

check_sanity($ps);
# Test re-requests in lua.
# - fetch zones.z1() then fetch zones.z2()
# - return z1 or z2 or netiher
# - fetch all three zones
# - hit the same zone multiple times

# Test delayed read (timeout)

# Test Lua logging (see t/watcher.t)
{
    note("Test Lua logging:" . __LINE__);

    my $be = $mbe[0];
    my $watcher = $p_srv->new_sock;
    print $watcher "watch proxyuser proxyreqs\n";
    is(<$watcher>, "OK\r\n", "watcher enabled");

    # log(msg)
    print $ps "get /logtest/a\r\n";
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_user msg=testing manual log messages/,
        "log a manual message");
    is(scalar <$ps>, "END\r\n", "logtest END");

    # log_req(r, res)
    my $cmd = "get /logreqtest/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "got passthru for log");
    print $be "END\r\n";
    is(scalar <$ps>, "END\r\n", "got END from log test");
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_req elapsed=\d+ type=105 code=17 status=0 be=127.0.0.1:11411 detail=logreqtest req=get \/logreqtest\/a/, "found request log entry");

    # test log_req with nil res (should be 0's in places)
    # log_reqsample()
}

# Basic proxy stats validation

# Test user stats

check_sanity($ps);
# Test await arguments (may move to own file?)
# TODO: the results table from mcp.await() contains all of the results so far,
# regardless of the mode.
# need some tests that show this.
{
    note("Test await argument:" . __LINE__);

    subtest 'Await hits all 3 backends' => sub {
        # be_recv must receive hit from all three backends
        my $key = "/awaitbasic/a";
        my $ps_send = "get $key\r\n";
        my @be_send = ["VALUE $key 0 2\r\nok\r\nEND\r\n"];
        proxy_test(
            ps_send => $ps_send,
            be_recv => {0 => [$ps_send], 1 => [$ps_send], 2 => [$ps_send]},
            be_send => {0 => @be_send, 1 => @be_send, 2 => @be_send},
            ps_recv => ["VALUE $key 0 11\r\n", "hit hit hit\r\n", "END\r\n"],
        );
    };

    my $cmd;
    my $key;

    # await(r, p, 1)
    $key = "/awaitone/a";
    $cmd = "get $key\r\n";
    print $ps $cmd;
    for my $be (@mbe) {
        is(scalar <$be>, $cmd, "awaitone backend req");
        print $be "VALUE $key 0 2\r\nok\r\nEND\r\n";
    }
    is(scalar <$ps>, "VALUE $key 0 1\r\n", "response from await");
    is(scalar <$ps>, "1\r\n", "looking for a single response");
    is(scalar <$ps>, "END\r\n", "end from await");

    # await(r, p(3+), 2)
    $key = "/awaitone/b";
    $cmd = "get $key\r\n";
    print $ps $cmd;
    for my $be (@mbe) {
        is(scalar <$be>, $cmd, "awaitone backend req");
        print $be "VALUE $key 0 2\r\nok\r\nEND\r\n";
    }
    is(scalar <$ps>, "VALUE $key 0 1\r\n", "response from await");
    is(scalar <$ps>, "2\r\n", "looking two responses");
    is(scalar <$ps>, "END\r\n", "end from await");

    # await(r, p, 1, mcp.AWAIT_GOOD)
    $key = "/awaitgood/a";
    $cmd = "get $key\r\n";
    print $ps $cmd;
    for my $be (@mbe) {
        is(scalar <$be>, $cmd, "awaitgood backend req");
        print $be "VALUE $key 0 2\r\nok\r\nEND\r\n";
    }
    is(scalar <$ps>, "VALUE $key 0 1\r\n", "response from await");
    is(scalar <$ps>, "1\r\n", "looking for a single response");
    is(scalar <$ps>, "END\r\n", "end from await");
    # should test above with first response being err, second good, third
    # miss, and a few similar iterations.

    # await(r, p, 2, mcp.AWAIT_ANY)
    $key = "/awaitany/a";
    $cmd = "get $key\r\n";
    print $ps $cmd;
    for my $be (@mbe) {
        is(scalar <$be>, $cmd, "awaitany backend req");
        print $be "VALUE $key 0 2\r\nok\r\nEND\r\n";
    }
    is(scalar <$ps>, "VALUE $key 0 1\r\n", "response from await");
    is(scalar <$ps>, "2\r\n", "looking for a two responses");
    is(scalar <$ps>, "END\r\n", "end from await");

    # await(r, p, 2, mcp.AWAIT_OK)
    # await(r, p, 1, mcp.AWAIT_FIRST)
    # more AWAIT_FIRST tests? to see how much it waits on/etc.
    # await(r, p, 2, mcp.AWAIT_FASTGOOD)
    # - should return 1 res on good, else wait for N non-error responses
    $key = "/awaitfastgood/a";
    $cmd = "get $key\r\n";
    print $ps $cmd;
    my $fbe = $mbe[0];
    is(scalar <$fbe>, $cmd, "awaitfastgood backend req");
    print $fbe "VALUE $key 0 2\r\nok\r\nEND\r\n";
    # Should have response after the first hit.
    is(scalar <$ps>, "VALUE $key 0 2\r\n", "response from await");
    is(scalar <$ps>, "ok\r\n", "await value");
    is(scalar <$ps>, "END\r\n", "end from await");
    for my $be ($mbe[1], $mbe[2]) {
        is(scalar <$be>, $cmd, "awaitfastgood backend req");
        print $be "VALUE $key 0 2\r\nok\r\nEND\r\n";
    }

    # test three pools, second response returns good. should have a hit.
    print $ps $cmd;
    for my $be (@mbe) {
        is(scalar <$be>, $cmd, "awaitfastgood backend req");
    }
    $fbe = $mbe[0];
    print $fbe "END\r\n";
    $fbe = $mbe[1];
    print $fbe "VALUE $key 0 2\r\nun\r\nEND\r\n";
    is(scalar <$ps>, "VALUE $key 0 2\r\n", "response from await");
    is(scalar <$ps>, "un\r\n", "await value");
    is(scalar <$ps>, "END\r\n", "end from await");
    $fbe = $mbe[2];
    print $fbe "END\r\n";

    # test three pools, but third returns good. should have returned already
    print $ps $cmd;
    for my $be ($mbe[0], $mbe[1]) {
        is(scalar <$be>, $cmd, "awaitfastgood backend req");
        print $be "END\r\n";
    }
    $fbe = $mbe[2];
    is(scalar <$fbe>, $cmd, "awaitfastgood backend req");
    print $fbe "VALUE $key 0 2\r\nnu\r\nEND\r\n";
    is(scalar <$ps>, "END\r\n", "miss from awaitfastgood");

    # Testing a set related to fastgood. waiting for two responses.
    $cmd = "set $key 0 0 2\r\nmo\r\n";
    print $ps $cmd;
    for my $be ($mbe[0], $mbe[1]) {
        is(scalar <$be>, "set $key 0 0 2\r\n", "set backend req");
        is(scalar <$be>, "mo\r\n", "set backend data");
        print $be "STORED\r\n";
    }
    is(scalar <$ps>, "STORED\r\n", "got stored from await");
    $fbe = $mbe[2];
    is(scalar <$fbe>, "set $key 0 0 2\r\n", "set backend req");
    is(scalar <$fbe>, "mo\r\n", "set backend data");
    print $fbe "STORED\r\n";

    # Testing another set; ensure it isn't returning early.
    my $s = IO::Select->new();
    $s->add($ps);
    print $ps $cmd;
    for my $be (@mbe) {
        is(scalar <$be>, "set $key 0 0 2\r\n", "set backend req");
        is(scalar <$be>, "mo\r\n", "set backend data");
    }
    $fbe = $mbe[0];
    print $fbe "STORED\r\n";
    my @readable = $s->can_read(0.25);
    is(scalar @readable, 0, "set doesn't return early");
    for my $be ($mbe[1], $mbe[2]) {
        print $be "STORED\r\n";
    }
    is(scalar <$ps>, "STORED\r\n", "set completed normally");

    # await(r, p, 1, mcp.AWAIT_BACKGROUND) - ensure res without waiting
    $key = "/awaitbg/a";
    $cmd = "get $key\r\n";
    print $ps $cmd;
    # check we can get a response _before_ the backends are consulted.
    is(scalar <$ps>, "VALUE $key 0 1\r\n", "response from await");
    is(scalar <$ps>, "0\r\n", "looking for zero responses");
    is(scalar <$ps>, "END\r\n", "end from await");
    for my $be (@mbe) {
        is(scalar <$be>, $cmd, "awaitbg backend req");
        print $be "VALUE $key 0 2\r\nok\r\nEND\r\n";
    }

    # test hitting a pool normally then hit mcp.await()
    # test hitting mcp.await() then a pool normally
}

check_sanity($ps);

{
    note("Test await_logerrors:" . __LINE__);

    my $watcher = $p_srv->new_sock;
    print $watcher "watch proxyreqs\n";
    is(<$watcher>, "OK\r\n", "watcher enabled");

    # test logging errors from special await.
    my $key = "/awaitlogerr/a";
    my $cmd = "set $key 0 0 5\r\n";
    print $ps $cmd . "hello\r\n";
    # respond from the first backend normally, then other two with errors.
    my $be = $mbe[0];
    is(scalar <$be>, $cmd, "await_logerrors backend req");
    is(scalar <$be>, "hello\r\n", "await_logerrors set payload");
    print $be "STORED\r\n";

    is(scalar <$ps>, "STORED\r\n", "block until await responded");
    # now ship some errors.
    for my $be ($mbe[1], $mbe[2]) {
        is(scalar <$be>, $cmd, "await_logerrors backend req");
        is(scalar <$be>, "hello\r\n", "await_logerrors set payload");
        print $be "SERVER_ERROR out of memory\r\n";
    }

    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_req elapsed=\d+ type=\d+ code=\d+ status=-1 be=(\S+) detail=write_failed req=set \/awaitlogerr\/a/, "await_logerrors log entry 1");
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_req elapsed=\d+ type=\d+ code=\d+ status=-1 be=(\S+) detail=write_failed req=set \/awaitlogerr\/a/, "await_logerrors log entry 2");

    # Repeat the logreqtest to ensure we only got the log lines we expected.
    $cmd = "get /logreqtest/a\r\n";
    print $ps $cmd;
    is(scalar <$be>, $cmd, "got passthru for log");
    print $be "END\r\n";
    is(scalar <$ps>, "END\r\n", "got END from log test");
    like(<$watcher>, qr/ts=(\S+) gid=\d+ type=proxy_req elapsed=\d+ type=105 code=17 status=0 be=127.0.0.1:11411 detail=logreqtest req=get \/logreqtest\/a/, "found request log entry");
}

check_sanity($ps);

# Test out of spec commands from client
# - wrong # of tokens
# - bad key size
# - etc

# Test errors/garbage from server
# - certain errors pass through to the client, most close the backend.
# - should be able to retrieve the error message
{
    note("Test error/garbage from backend:" . __LINE__);

    my $be = $mbe[0];
    print $ps "set /b/foo 0 0 2\r\nhi\r\n";
    is(scalar <$be>, "set /b/foo 0 0 2\r\n", "received set cmd");
    is(scalar <$be>, "hi\r\n", "received set data");
    # Send a classic back up the pipe.
    my $msg = "SERVER_ERROR object too large for cache\r\n";
    print $be $msg;
    is(scalar <$ps>, $msg, "client received error message");

    print $ps "get /b/foo\r\n";
    is(scalar <$be>, "get /b/foo\r\n", "backend still works");
    print $be "END\r\n";
    is(scalar <$ps>, "END\r\n", "got end back");

    # ERROR and CLIENT_ERROR should both break the backend.
    print $ps "get /b/moo\r\n";
    is(scalar <$be>, "get /b/moo\r\n", "received get command");
    $msg = "CLIENT_ERROR bad command line format\r\n";
    my $data;
    print $be $msg;
    is(scalar <$ps>, $msg, "client received error message");
    my $read = $be->read($data, 1);
    is($read, 0, "backend disconnected");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    print $ps "get /b/too\r\n";
    is(scalar <$be>, "get /b/too\r\n", "received get command");
    $msg = "ERROR unhappy\r\n";
    print $be $msg;
    is(scalar <$ps>, $msg, "client received error message");
    $read = $be->read($data, 1);
    is($read, 0, "backend disconnected");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    # Sometimes blank ERRORS can be sent.
    print $ps "get /b/zoo\r\n";
    is(scalar <$be>, "get /b/zoo\r\n", "received get command");
    $msg = "ERROR\r\n";
    print $be $msg;
    is(scalar <$ps>, $msg, "client received error message");
    $read = $be->read($data, 1);
    is($read, 0, "backend disconnected");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    # Ensure garbage doesn't surface to client.
    print $ps "get /b/doo\r\n";
    is(scalar <$be>, "get /b/doo\r\n", "received get command");
    print $be "garbage\r\n"; # don't need the \r\n but it makes tests easier
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "generic backend error");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    # Check errors from pipelined commands past a CLIENT_ERROR
    print $ps "get /b/quu\r\nget /b/muu\r\n";
    is(scalar <$be>, "get /b/quu\r\n", "received get command");
    is(scalar <$be>, "get /b/muu\r\n", "received next get command");
    print $be "CLIENT_ERROR bad protocol\r\nEND\r\n";
    is(scalar <$ps>, "CLIENT_ERROR bad protocol\r\n", "backend error");
    is(scalar <$ps>, "SERVER_ERROR backend failure\r\n", "backend error");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    # Check that lua handles errors properly.
    print $ps "get /errcheck/a\r\n";
    is(scalar <$be>, "get /errcheck/a\r\n", "received get command");
    print $be "ERROR test1\r\n";
    is(scalar <$ps>, "ERROR\r\n", "lua saw correct error code");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    print $ps "get /errcheck/b\r\n";
    is(scalar <$be>, "get /errcheck/b\r\n", "received get command");
    print $be "CLIENT_ERROR test2\r\n";
    is(scalar <$ps>, "CLIENT_ERROR\r\n", "lua saw correct error code");

    $be = $mbe[0] = accept_backend($mocksrvs[0]);

    print $ps "get /errcheck/c\r\n";
    is(scalar <$be>, "get /errcheck/c\r\n", "received get command");
    print $be "SERVER_ERROR test3\r\n";
    is(scalar <$ps>, "SERVER_ERROR\r\n", "lua saw correct error code");
}

check_sanity($ps);
done_testing();

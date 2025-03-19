# Memcached

Memcached is a high performance multithreaded event-based key/value cache
store intended to be used in a distributed system.

See: https://memcached.org/about

A fun story explaining usage: https://memcached.org/tutorial

If you're having trouble, try the wiki: https://memcached.org/wiki

If you're trying to troubleshoot odd behavior or timeouts, see:
https://memcached.org/timeouts

https://memcached.org/ is a good resource in general. Please use the mailing
list to ask questions, github issues aren't seen by everyone!

## Dependencies

* libevent - https://www.monkey.org/~provos/libevent/ (libevent-dev)
* libseccomp (optional, experimental, linux) - enables process restrictions for
  better security. Tested only on x86-64 architectures.
* openssl (optional) - enables TLS support. need relatively up to date
  version. pkg-config is needed to find openssl dependencies (such as -lz).

## Building from tarball

If you downloaded this from the tarball, compilation is the standard process:

```
./configure
make
make test # optional
make install
```

If you want TLS support, install OpenSSL's development packages and change the
configure line:

```
./configure --enable-tls
```

If you want to enable the memcached proxy:

```
./configure --enable-proxy
```

## Building from git

To build memcached in your machine from local repo you will have to install
autotools, automake and libevent. In a debian based system that will look
like this

```
sudo apt-get install autotools-dev automake libevent-dev
```

After that you can build memcached binary using automake

```
cd memcached
./autogen.sh
./configure
make
make test
```

It should create the binary in the same folder, which you can run

```
./memcached
```

You can telnet into that memcached to ensure it is up and running

```
telnet 127.0.0.1 11211
stats
```

IF BUILDING PROXY, AN EXTRA STEP IS NECESSARY:

The proxy has some additional vendor dependency code that we keep out of the
tree.

```
cd memcached
cd vendor
./fetch.sh
cd ..
./autogen.sh
./configure --enable-proxy
make
make test
```

## Environment

Be warned that the -k (mlockall) option to memcached might be
dangerous when using a large cache. Just make sure the memcached machines
don't swap.  memcached does non-blocking network I/O, but not disk.  (it
should never go to disk, or you've lost the whole point of it)

## Build status

See https://build.memcached.org/ for multi-platform regression testing status.

## Bug reports

Feel free to use the issue tracker on github.

**If you are reporting a security bug** please contact a maintainer privately.
We follow responsible disclosure: we handle reports privately, prepare a
patch, allow notifications to vendor lists. Then we push a fix release and your
bug can be posted publicly with credit in our release notes and commit
history.

## Website

* https://www.memcached.org

## Contributing

See https://github.com/memcached/memcached/wiki/DevelopmentRepos

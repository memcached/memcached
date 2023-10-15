# Memcached Challenge

Inspired by [Arthur O’Dwyer's Blog](https://quuxplusone.github.io/blog/2022/01/06/memcached-interview/), I start this challenge as a engineering interview (a little big different from the blog):

1. Fork [**memcached** - master](https://github.com/memcached/memcached/), and build it;

I suggest using Linux os to do this, since there may be errors in compile stage in MacOS (not test on Windows).

```
git clone --depth=1 https://github.com/memcached/memcached.git

sh autogen.sh
./configure
make
```

2. Provide a `mult` method to multiply a unsigned instance number to a stored number.

Here is the demo from my impl:

![demo](https://imgbed.scubot.com/image/202310151637925.png)

For more details, checkout the [>**PR**<](https://github.com/hx-w/memcached/pull/1).

I DO need some suggests, just leave a issue.
